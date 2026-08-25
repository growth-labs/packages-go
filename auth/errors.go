package auth

import "fmt"

// Code is a stable, bounded authentication failure category.
type Code string

const (
	CodeInvalidConfig       Code = "invalid_config"
	CodeInvalidProvider     Code = "invalid_provider"
	CodeInvalidState        Code = "invalid_state"
	CodeMissingPKCE         Code = "missing_pkce_verifier"
	CodeInvalidToken        Code = "invalid_token"
	CodeInvalidSignature    Code = "invalid_signature"
	CodeWrongIssuer         Code = "wrong_issuer"
	CodeWrongAudience       Code = "wrong_audience"
	CodeTokenExpired        Code = "token_expired"
	CodeTokenNotYetValid    Code = "token_not_yet_valid"
	CodeTokenIssuedInFuture Code = "token_issued_in_future"
	CodeJWKSUnavailable     Code = "jwks_unavailable"
	CodeSecretUnavailable   Code = "auth_service_unavailable"
)

// Error reports an authentication failure without reflecting sensitive input.
type Error struct {
	Code Code
	Err  error
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	return string(e.Code)
}

func (e *Error) Unwrap() error { return e.Err }

// IsCode reports whether err carries code.
func IsCode(err error, code Code) bool {
	for err != nil {
		if authErr, ok := err.(*Error); ok && authErr.Code == code {
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
