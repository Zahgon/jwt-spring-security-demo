// Package rest holds the two example endpoints that demonstrate authority-based
// access: one open to any ROLE_USER, one restricted to ROLE_ADMIN. Both return
// a constant, so the demo shows the authorisation decision and nothing else.
package rest

import (
	"net/http"

	"github.com/szerhusenBC/jwt-spring-security-demo/internal/web"
)

// PersonController serves GET /api/person.
type PersonController struct {
	responder *web.Responder
}

// NewPersonController builds the controller.
func NewPersonController(responder *web.Responder) *PersonController {
	return &PersonController{responder: responder}
}

// person is the fixed payload the endpoint returns.
type person struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

// GetPerson returns the example person.
func (c *PersonController) GetPerson(w http.ResponseWriter, r *http.Request) {
	c.responder.WriteJSON(w, http.StatusOK, person{Name: "John Doe", Email: "john.doe@test.org"})
}
