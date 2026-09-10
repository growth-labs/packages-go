package email

import "errors"

// Unsubmitted marks evidence that the transport did not accept a send. Only
// these errors may be automatically retried. Network ambiguity is not
// evidence: a request whose response was lost may well have been delivered,
// so it is deliberately left unmarked and must not be retried automatically.
type unsubmittedError struct{ error }

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
