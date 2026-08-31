package security_test

import (
	"context"
	"testing"

	"github.com/szerhusenBC/jwt-spring-security-demo/internal/logging"
	"github.com/szerhusenBC/jwt-spring-security-demo/internal/security"
)

// SecurityUtilsTest.

func TestGetCurrentUsername(t *testing.T) {
	securityUtils := security.NewSecurityUtils(logging.Discard().Logger("test"))
	ctx := security.WithAuthentication(context.Background(), &security.Authentication{
		Principal:     "admin",
		Credentials:   "admin",
		Authenticated: true,
	})

	username, ok := securityUtils.CurrentUsername(ctx)

	if !ok || username != "admin" {
		t.Errorf("CurrentUsername() = %q, %v; want \"admin\", true", username, ok)
	}
}

func TestGetCurrentUsernameForNoAuthenticationInContext(t *testing.T) {
	securityUtils := security.NewSecurityUtils(logging.Discard().Logger("test"))

	username, ok := securityUtils.CurrentUsername(context.Background())

	if ok {
		t.Errorf("CurrentUsername() = %q, true; want empty", username)
	}
}
