package rest

import (
	"net/http"

	"github.com/szerhusenBC/jwt-spring-security-demo/internal/web"
)

// AdminProtectedController serves GET /api/hiddenmessage.
type AdminProtectedController struct {
	responder *web.Responder
}

// NewAdminProtectedController builds the controller.
func NewAdminProtectedController(responder *web.Responder) *AdminProtectedController {
	return &AdminProtectedController{responder: responder}
}

// hiddenMessage is the fixed payload the endpoint returns.
type hiddenMessage struct {
	Message string `json:"message"`
}

// GetAdminProtectedGreeting returns the hidden message.
func (c *AdminProtectedController) GetAdminProtectedGreeting(w http.ResponseWriter, r *http.Request) {
	c.responder.WriteJSON(w, http.StatusOK, hiddenMessage{Message: "this is a hidden message!"})
}
