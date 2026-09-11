package app_test

import (
	"fmt"
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

// TestAddrAndBanner covers the two accessors main() uses when it starts the
// server and prints the Spring Boot banner; nothing else in the suite reads them.
func TestAddrAndBanner(t *testing.T) {
	application := testutil.NewApplication(t)

	want := fmt.Sprintf(":%d", application.Config.Server.Port)
	if got := application.Addr(); got != want {
		t.Errorf("Addr() = %q, want %q", got, want)
	}

	if application.Banner() == "" {
		t.Error("Banner() is empty; main() prints it at startup")
	}
}
