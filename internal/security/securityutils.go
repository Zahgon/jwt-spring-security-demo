package security

import (
	"context"

	"github.com/szerhusenBC/jwt-spring-security-demo/internal/logging"
)

// SecurityUtils reads the current principal out of a request context. The
// original is a static utility over a ThreadLocal; here the context is passed
// explicitly, and the logger is held rather than looked up statically.
type SecurityUtils struct {
	log *logging.Logger
}

// NewSecurityUtils builds the utility.
func NewSecurityUtils(log *logging.Logger) *SecurityUtils { return &SecurityUtils{log: log} }

// CurrentUsername returns the login of the current user, and false when the
// context carries no authentication or no name can be read from it.
func (s *SecurityUtils) CurrentUsername(ctx context.Context) (string, bool) {
	authentication := AuthenticationFrom(ctx)
	if authentication == nil {
		s.log.Debug("no authentication in security context found")
		return "", false
	}

	username := authentication.Name()
	s.log.Debug("found username '%s' in security context", username)

	return username, username != ""
}
