// Package rest holds the endpoints that authenticate a user and report who the
// current user is.
package rest

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/szerhusenBC/jwt-spring-security-demo/internal/security"
	"github.com/szerhusenBC/jwt-spring-security-demo/internal/security/jwt"
	"github.com/szerhusenBC/jwt-spring-security-demo/internal/security/rest/dto"
	"github.com/szerhusenBC/jwt-spring-security-demo/internal/web"
)

// AuthenticationController exchanges credentials for a token.
type AuthenticationController struct {
	tokenProvider         *jwt.TokenProvider
	authenticationManager *security.AuthenticationManager
	responder             *web.Responder
}

// NewAuthenticationController builds the controller.
func NewAuthenticationController(
	tokenProvider *jwt.TokenProvider,
	authenticationManager *security.AuthenticationManager,
	responder *web.Responder,
) *AuthenticationController {
	return &AuthenticationController{
		tokenProvider:         tokenProvider,
		authenticationManager: authenticationManager,
		responder:             responder,
	}
}

// jwtToken is the response body. The member is "id_token", not "idToken" — the
// original renames it with @JsonProperty.
type jwtToken struct {
	IDToken string `json:"id_token"`
}

// Authorize authenticates the submitted credentials and returns a token.
//
// The token is returned twice: in the body, and in an Authorization response
// header, which is what the bundled JavaScript client reads.
func (c *AuthenticationController) Authorize(w http.ResponseWriter, r *http.Request) {
	loginDto, err := decodeLoginDto(r)
	if err != nil {
		c.responder.SendError(w, r, http.StatusBadRequest, "JSON parse error: "+err.Error())
		return
	}

	if fieldErrors := loginDto.Validate(); len(fieldErrors) > 0 {
		c.responder.SendValidationError(w, r, dto.ObjectName, fieldErrors)
		return
	}

	authentication, err := c.authenticationManager.Authenticate(r.Context(), loginDto.GetUsername(), loginDto.GetPassword())
	if err != nil {
		// An authentication failure escaping the controller is caught by the
		// security chain and handed to the entry point, which answers 401 with
		// the failure's own message.
		c.responder.SendError(w, r, http.StatusUnauthorized, authenticationMessage(err))
		return
	}

	token := c.tokenProvider.CreateToken(authentication, loginDto.IsRememberMe())

	w.Header().Set(jwt.AuthorizationHeader, "Bearer "+token)
	c.responder.WriteJSON(w, http.StatusOK, jwtToken{IDToken: token})
}

func decodeLoginDto(r *http.Request) (dto.LoginDto, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return dto.LoginDto{}, err
	}

	var loginDto dto.LoginDto
	if err := json.Unmarshal(body, &loginDto); err != nil {
		return dto.LoginDto{}, err
	}
	return loginDto, nil
}

// authenticationMessage returns the text a failed authentication reports.
// Anything that is not a recognised authentication failure would have been a
// server error in the original, but the only failures Authenticate returns are
// authentication ones.
func authenticationMessage(err error) string {
	var notActivated *security.NotActivatedError
	if errors.As(err, &notActivated) {
		return notActivated.Error()
	}
	return security.ErrBadCredentials.Error()
}
