// Package springboot reproduces the error body Spring Boot's
// DefaultErrorAttributes renders. Every non-2xx response the original produces
// — whether it comes from the security filter chain, from request validation,
// or from the dispatcher failing to find a handler — is forwarded to /error and
// rendered through this one shape, so the port needs it in exactly one place
// too.
package springboot

import (
	"net/http"
	"time"

	"github.com/szerhusenBC/jwt-spring-security-demo/internal/deps/springvalidation"
)

// timestampLayout is Jackson's StdDateFormat: ISO-8601 with milliseconds and a
// numeric UTC offset, which for a UTC instant prints the literal "+0000".
const timestampLayout = "2006-01-02T15:04:05.000-0700"

// ErrorAttributes is the JSON body of every error response. Member order is
// the order Jackson emits and is part of the observable bytes; "errors" is
// present only for validation failures.
type ErrorAttributes struct {
	Timestamp string                        `json:"timestamp"`
	Status    int                           `json:"status"`
	Error     string                        `json:"error"`
	Errors    []springvalidation.FieldError `json:"errors,omitempty"`
	Message   string                        `json:"message"`
	Path      string                        `json:"path"`
}

// NewErrorAttributes builds the body for a plain error. The reason phrase is
// derived from the status, as Spring derives it from HttpStatus.
func NewErrorAttributes(now time.Time, status int, message, path string) ErrorAttributes {
	return ErrorAttributes{
		Timestamp: now.UTC().Format(timestampLayout),
		Status:    status,
		Error:     http.StatusText(status),
		Message:   message,
		Path:      path,
	}
}
