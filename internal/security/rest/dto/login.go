// Package dto holds the request body of the authentication endpoint.
package dto

import (
	"github.com/szerhusenBC/jwt-spring-security-demo/internal/deps/springvalidation"
)

// ObjectName is the name the validation errors report the bound object under.
// Spring derives it from the parameter's type; it appears in the response body,
// so it is pinned here.
const ObjectName = "loginDto"

// LoginDto carries a user's credentials.
//
// The members are pointers so that "absent" and "present but empty" stay
// distinguishable, which is what @NotNull and @Size respectively test for.
type LoginDto struct {
	Username   *string `json:"username"`
	Password   *string `json:"password"`
	RememberMe *bool   `json:"rememberMe"`
}

// GetUsername returns the submitted username, or the empty string when absent.
func (d LoginDto) GetUsername() string {
	if d.Username == nil {
		return ""
	}
	return *d.Username
}

// GetPassword returns the submitted password, or the empty string when absent.
func (d LoginDto) GetPassword() string {
	if d.Password == nil {
		return ""
	}
	return *d.Password
}

// IsRememberMe reports whether a longer-lived token was asked for. An absent
// member means false.
func (d LoginDto) IsRememberMe() bool {
	return d.RememberMe != nil && *d.RememberMe
}

// Validate applies the Bean Validation constraints the original declares on
// this DTO and returns one field error per violation.
func (d LoginDto) Validate() []springvalidation.FieldError {
	return springvalidation.Validate(ObjectName, []springvalidation.Field{
		{
			Name:        "username",
			TypeName:    "java.lang.String",
			Value:       stringValue(d.Username),
			Constraints: []springvalidation.Constraint{springvalidation.NotNull(), springvalidation.Size(1, 50)},
		},
		{
			Name:        "password",
			TypeName:    "java.lang.String",
			Value:       stringValue(d.Password),
			Constraints: []springvalidation.Constraint{springvalidation.NotNull(), springvalidation.Size(4, 100)},
		},
	})
}

// stringValue converts an optional member into the "rejected value" a field
// error reports: the string itself, or nil when the member was absent.
func stringValue(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}
