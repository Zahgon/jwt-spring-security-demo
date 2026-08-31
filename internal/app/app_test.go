package app_test

import (
	"testing"

	"github.com/szerhusenBC/jwt-spring-security-demo/internal/testutil"
)

// TestContextLoads is JwtDemoApplicationTest#contextLoads: the application
// wiring initialises without error.
func TestContextLoads(t *testing.T) {
	application := testutil.NewApplication(t)

	if application.Handler == nil {
		t.Fatal("the application was built without a request handler")
	}
}
