package fulcrumprojects

import "fmt"

// Code is a stable, bounded failure category.
type Code string

const (
	// Configuration-class: the caller's setup is wrong; never retryable
	// without a config change.
	CodeInvalidConfig  Code = "invalid_config"
	CodeInvalidRequest Code = "invalid_request"
	CodeUnauthorized   Code = "unauthorized"
	CodeForbidden      Code = "forbidden"

	// Sync-class: the write raced the store. Retryable exactly once after a
	// fresh snapshot or changes read; the caller decides, never the client.
	CodeEpochMismatch Code = "sync_epoch_mismatch"
	CodeConflict      Code = "conflict"

	// Transport-class: the call itself failed.
	CodeTransportUnavailable Code = "transport_unavailable"
	CodeRateLimited          Code = "rate_limited"
	CodeUnexpectedResponse   Code = "unexpected_response"
)

// Class reports which class code belongs to: configuration, sync or
// transport.
func (c Code) Class() string {
	switch c {
	case CodeInvalidConfig, CodeInvalidRequest, CodeUnauthorized, CodeForbidden:
		return "configuration"
	case CodeEpochMismatch, CodeConflict:
		return "sync"
	default:
		return "transport"
	}
}

// Error reports a fulcrumprojects failure without reflecting the credential
// or a request body into its message.
type Error struct {
	Code   Code
	Status int
	Err    error
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Code, e.Err)
	}
	return string(e.Code)
}

func (e *Error) Unwrap() error { return e.Err }

// IsCode reports whether err carries code, unwrapping as needed.
func IsCode(err error, code Code) bool {
	for err != nil {
		if fpErr, ok := err.(*Error); ok && fpErr.Code == code {
			return true
		}
		unwrapper, ok := err.(interface{ Unwrap() error })
		if !ok {
			break
		}
		err = unwrapper.Unwrap()
	}
	return false
}

func errorf(code Code, status int, format string, args ...any) error {
	return &Error{Code: code, Status: status, Err: fmt.Errorf(format, args...)}
}
