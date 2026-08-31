package security

import (
	"net/http"
)

// ErrorResponder renders an error status and message as the application's
// standard JSON error body. The web layer supplies it so that the security
// handlers stay free of any knowledge of how a body is written.
type ErrorResponder interface {
	SendError(w http.ResponseWriter, r *http.Request, status int, message string)
}

// AuthenticationEntryPoint answers a request that reached a secured resource
// without usable credentials. There is no login page to redirect to, so the
// answer is a plain 401.
type AuthenticationEntryPoint struct {
	responder ErrorResponder
}

// NewAuthenticationEntryPoint builds the entry point.
func NewAuthenticationEntryPoint(responder ErrorResponder) *AuthenticationEntryPoint {
	return &AuthenticationEntryPoint{responder: responder}
}

// Commence sends 401 with the authentication failure's message.
func (e *AuthenticationEntryPoint) Commence(w http.ResponseWriter, r *http.Request, message string) {
	e.responder.SendError(w, r, http.StatusUnauthorized, message)
}

// AccessDeniedHandler answers a request from a principal that is authenticated
// but lacks the authority the resource requires. There is no error page to
// redirect to, so the answer is a plain 403.
type AccessDeniedHandler struct {
	responder ErrorResponder
}

// NewAccessDeniedHandler builds the handler.
func NewAccessDeniedHandler(responder ErrorResponder) *AccessDeniedHandler {
	return &AccessDeniedHandler{responder: responder}
}

// Handle sends 403 with the access-denied message.
func (h *AccessDeniedHandler) Handle(w http.ResponseWriter, r *http.Request, message string) {
	h.responder.SendError(w, r, http.StatusForbidden, message)
}
