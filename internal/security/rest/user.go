package rest

import (
	"net/http"

	"github.com/szerhusenBC/jwt-spring-security-demo/internal/security/service"
	"github.com/szerhusenBC/jwt-spring-security-demo/internal/web"
)

// UserController reports the currently authenticated account.
type UserController struct {
	userService *service.UserService
	responder   *web.Responder
}

// NewUserController builds the controller.
func NewUserController(userService *service.UserService, responder *web.Responder) *UserController {
	return &UserController{userService: userService, responder: responder}
}

// GetActualUser returns the account behind the request's token.
func (c *UserController) GetActualUser(w http.ResponseWriter, r *http.Request) {
	user, found, err := c.userService.GetUserWithAuthorities(r.Context())
	if err != nil || !found {
		// The original calls Optional#get here, so an absent user surfaces as a
		// server error rather than a 404.
		c.responder.SendError(w, r, http.StatusInternalServerError, "No message available")
		return
	}
	c.responder.WriteJSON(w, http.StatusOK, user)
}
