// Package web is the HTTP plumbing the original inherits from Spring MVC and
// Spring Boot: writing indented JSON bodies, rendering the standard error
// envelope, dispatching to handlers, and serving the static client.
package web

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/szerhusenBC/jwt-spring-security-demo/internal/deps/jackson"
	"github.com/szerhusenBC/jwt-spring-security-demo/internal/deps/springboot"
	"github.com/szerhusenBC/jwt-spring-security-demo/internal/deps/springvalidation"
)

// ContentTypeJSON is the value Spring writes for a JSON body. The absence of a
// space before "charset" is what Spring emits, and is reproduced here.
const ContentTypeJSON = "application/json;charset=UTF-8"

// Responder writes response bodies.
type Responder struct {
	// now supplies the instant stamped into error bodies; it is a field so
	// tests can pin it.
	now func() time.Time
}

// NewResponder builds a responder using the wall clock.
func NewResponder() *Responder { return &Responder{now: time.Now} }

// WriteJSON writes value as an indented JSON body with the given status.
func (r *Responder) WriteJSON(w http.ResponseWriter, status int, value any) {
	body, err := jackson.Marshal(value)
	if err != nil {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", ContentTypeJSON)
	w.WriteHeader(status)
	w.Write(body)
}

// SendError renders the standard error envelope, the counterpart of
// HttpServletResponse#sendError forwarding to Spring Boot's /error handler.
func (r *Responder) SendError(w http.ResponseWriter, req *http.Request, status int, message string) {
	r.WriteJSON(w, status, springboot.NewErrorAttributes(r.now(), status, message, req.URL.Path))
}

// SendValidationError renders the 400 a failed @Valid @RequestBody produces:
// the standard envelope with an "errors" array between "error" and "message",
// and a top-level message counting the violations.
func (r *Responder) SendValidationError(w http.ResponseWriter, req *http.Request, objectName string, fieldErrors []springvalidation.FieldError) {
	attributes := springboot.NewErrorAttributes(r.now(), http.StatusBadRequest,
		"Validation failed for object='"+objectName+"'. Error count: "+strconv.Itoa(len(fieldErrors)), req.URL.Path)
	attributes.Errors = fieldErrors
	r.WriteJSON(w, http.StatusBadRequest, attributes)
}

// requestContentType reports the request's media type the way Spring reads it.
// When the header carries no charset, Spring appends the request's character
// encoding, which Spring Boot defaults to UTF-8; when the header is absent
// altogether, Spring falls back to application/octet-stream.
func requestContentType(r *http.Request) string {
	contentType := strings.TrimSpace(r.Header.Get("Content-Type"))
	if contentType == "" {
		return "application/octet-stream"
	}
	if !strings.Contains(strings.ToLower(contentType), "charset=") {
		contentType += ";charset=UTF-8"
	}
	return contentType
}

// isJSON reports whether the request body is declared as JSON.
func isJSON(r *http.Request) bool {
	mediaType, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";")
	return strings.EqualFold(strings.TrimSpace(mediaType), "application/json")
}
