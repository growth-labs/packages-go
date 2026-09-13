package email

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// RateLimitError is structured provider rate-limit evidence. StatusCode is 429
// for an HTTP rejection; Method is the JMAP method for a rateLimit error.
// RetryAfter is the provider's HTTP retry hint, capped at 24 hours; zero means
// absent, invalid, or already elapsed. Retry policy remains the caller's job.
// This error alone does not prove that a send was unsubmitted: require both
// IsRateLimited and IsUnsubmitted before automatically retrying a failed send.
type RateLimitError struct {
	StatusCode int
	Method     string
	RetryAfter time.Duration
}

func (e *RateLimitError) Error() string {
	if e.StatusCode != 0 {
		return fmt.Sprintf("fastmail: rate limited (http %d)", e.StatusCode)
	}
	return fmt.Sprintf("fastmail: %s rate limited", e.Method)
}

// IsRateLimited reports typed provider evidence, including through wrappers.
// It never interprets human-readable error descriptions as retry evidence.
func IsRateLimited(err error) bool {
	var target *RateLimitError
	return errors.As(err, &target) && target != nil
}

func retryAfter(header string) time.Duration {
	const maximum = 24 * time.Hour
	if header == "" {
		return 0
	}
	if seconds, err := strconv.ParseUint(header, 10, 64); err == nil {
		if seconds > uint64(maximum/time.Second) {
			return maximum
		}
		return time.Duration(seconds) * time.Second
	}
	when, err := http.ParseTime(header)
	if err != nil {
		return 0
	}
	delay := time.Until(when)
	if delay < 0 {
		return 0
	}
	if delay > maximum {
		return maximum
	}
	return delay
}

// Unsubmitted marks evidence that the transport did not accept a send. Only
// these errors can be considered for retry; permanent rejection may still
// require a caller correction. Network ambiguity is not
// evidence: a request whose response was lost may well have been delivered,
// so it is deliberately left unmarked and must not be retried automatically.
type unsubmittedError struct{ error }

func (e unsubmittedError) Unwrap() error { return e.error }

// Unsubmitted wraps err as proof that nothing was submitted. It returns nil
// for a nil error so callers can wrap unconditionally.
func Unsubmitted(err error) error {
	if err == nil {
		return nil
	}
	return unsubmittedError{err}
}

// IsUnsubmitted reports whether err carries proof that nothing was submitted.
func IsUnsubmitted(err error) bool { var target unsubmittedError; return errors.As(err, &target) }
