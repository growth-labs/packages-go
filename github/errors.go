package github

import "fmt"

// Code is a stable, bounded failure category.
type Code string

const (
	// Configuration-class: the caller's setup is wrong. Never retryable
	// without a config change.
	CodeInvalidConfig       Code = "invalid_config"
	CodeInvalidPrivateKey   Code = "invalid_private_key"
	CodeUnknownInstallation Code = "unknown_installation"
	CodeInvalidPermissions  Code = "invalid_permissions"

	// Transport-class: the failure is in the call itself. Retryable
	// through controlled remint; never papered over with an ambient
	// fallback.
	CodeTransportUnavailable Code = "transport_unavailable"
	CodeRateLimited          Code = "rate_limited"
	CodeCallBudgetExhausted  Code = "call_budget_exhausted"
	CodeDuplicateRead        Code = "duplicate_read_rejected"
	CodeUnexpectedResponse   Code = "unexpected_response"
)

// Class reports which of the two error classes code belongs to:
// "configuration" or "transport". A caller uses this to decide whether a
// failure is worth retrying at all.
func (c Code) Class() string {
	switch c {
	case CodeInvalidConfig, CodeInvalidPrivateKey, CodeUnknownInstallation, CodeInvalidPermissions:
		return "configuration"
	default:
		return "transport"
	}
}

// Error reports a github package failure without reflecting sensitive input
// (a private key, a token value) into its message.
type Error struct {
	Code Code
	Err  error
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
		if ghErr, ok := err.(*Error); ok && ghErr.Code == code {
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

func errorf(code Code, format string, args ...any) error {
	return &Error{Code: code, Err: fmt.Errorf(format, args...)}
}
