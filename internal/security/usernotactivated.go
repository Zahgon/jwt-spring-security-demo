package security

import "errors"

// ErrBadCredentials is Spring Security's BadCredentialsException. As in the
// original, an unknown account and a wrong password both report it, so that a
// caller cannot tell the two apart.
var ErrBadCredentials = errors.New("Bad credentials")

// NotActivatedError is thrown when a deactivated account tries to
// authenticate. It reaches the client verbatim, so the wording is fixed.
type NotActivatedError struct {
	Login string
}

func (e *NotActivatedError) Error() string { return "User " + e.Login + " was not activated" }
