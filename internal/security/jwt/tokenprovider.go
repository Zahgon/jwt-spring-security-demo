// Package jwt mints and validates the application's tokens and installs the
// resulting principal on incoming requests.
package jwt

import (
	"errors"
	"strings"
	"time"

	"github.com/szerhusenBC/jwt-spring-security-demo/internal/deps/jjwt"
	"github.com/szerhusenBC/jwt-spring-security-demo/internal/logging"
	"github.com/szerhusenBC/jwt-spring-security-demo/internal/security"
)

// authoritiesKey is the claim the granted authorities are packed into.
const authoritiesKey = "auth"

// TokenProvider creates and validates JSON Web Tokens.
type TokenProvider struct {
	key                        []byte
	tokenValidity              time.Duration
	tokenValidityForRememberMe time.Duration
	log                        *logging.Logger
	now                        func() time.Time
}

// NewTokenProvider builds a provider. secret is the decoded key material from
// jwt.base64-secret.
func NewTokenProvider(secret []byte, tokenValidity, tokenValidityForRememberMe time.Duration, log *logging.Logger) *TokenProvider {
	return &TokenProvider{
		key:                        secret,
		tokenValidity:              tokenValidity,
		tokenValidityForRememberMe: tokenValidityForRememberMe,
		log:                        log,
		now:                        time.Now,
	}
}

// CreateToken mints a token for an authenticated principal. rememberMe selects
// the longer of the two validity windows.
func (p *TokenProvider) CreateToken(authentication *security.Authentication, rememberMe bool) string {
	validity := p.tokenValidity
	if rememberMe {
		validity = p.tokenValidityForRememberMe
	}

	return jjwt.Sign(jjwt.Claims{
		Subject:    authentication.Name(),
		Auth:       strings.Join(authentication.Authorities, ","),
		Expiration: p.now().Add(validity),
	}, p.key)
}

// GetAuthentication rebuilds the principal a token stands for. The database is
// not consulted: everything the request needs is in the claims, which is what
// makes the API stateless.
func (p *TokenProvider) GetAuthentication(token string) (*security.Authentication, error) {
	claims, err := jjwt.Parse(token, p.key, p.now())
	if err != nil {
		return nil, err
	}

	authorities := strings.Split(claims.Auth, ",")
	principal := security.NewUserDetails(claims.Subject, "", authorities)

	return &security.Authentication{
		Principal:     principal,
		Credentials:   token,
		Authorities:   authorities,
		Authenticated: true,
	}, nil
}

// ValidateToken reports whether a token is usable, logging why it is not. The
// four categories below are the four exceptions the original catches, and the
// wording of each message is reproduced verbatim.
func (p *TokenProvider) ValidateToken(authToken string) bool {
	_, err := jjwt.Parse(authToken, p.key, p.now())
	switch {
	case err == nil:
		return true
	case errors.Is(err, jjwt.ErrSignature), errors.Is(err, jjwt.ErrMalformed):
		p.log.Info("Invalid JWT signature.")
		p.log.Trace("Invalid JWT signature trace: %v", err)
	case errors.Is(err, jjwt.ErrExpired):
		p.log.Info("Expired JWT token.")
		p.log.Trace("Expired JWT token trace: %v", err)
	case errors.Is(err, jjwt.ErrUnsupported):
		p.log.Info("Unsupported JWT token.")
		p.log.Trace("Unsupported JWT token trace: %v", err)
	case errors.Is(err, jjwt.ErrIllegalArgument):
		p.log.Info("JWT token compact of handler are invalid.")
		p.log.Trace("JWT token compact of handler are invalid trace: %v", err)
	}
	return false
}
