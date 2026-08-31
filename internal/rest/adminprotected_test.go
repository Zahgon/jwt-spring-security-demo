package rest_test

import (
	"net/http"
	"testing"

	"github.com/szerhusenBC/jwt-spring-security-demo/internal/testutil"
)

// AdminProtectedRestControllerTest.

func TestGetAdminProtectedGreetingForUser(t *testing.T) {
	application := testutil.NewApplication(t)
	token := application.GetTokenForLogin(t, "user", "password")

	response := application.Perform(t, testutil.WithToken(testutil.Get("/api/hiddenmessage"), token))

	if response.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d (body %s)", response.Code, http.StatusForbidden, response.Body)
	}
}

func TestGetAdminProtectedGreetingForAdmin(t *testing.T) {
	application := testutil.NewApplication(t)
	token := application.GetTokenForLogin(t, "admin", "admin")

	response := application.Perform(t, testutil.WithToken(testutil.Get("/api/hiddenmessage"), token))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body %s)", response.Code, http.StatusOK, response.Body)
	}
	want := "{\n  \"message\" : \"this is a hidden message!\"\n}"
	if got := response.Body.String(); got != want {
		t.Errorf("body =\n%s\nwant\n%s", got, want)
	}
}

func TestGetAdminProtectedGreetingForAnonymous(t *testing.T) {
	application := testutil.NewApplication(t)

	response := application.Perform(t, testutil.Get("/api/hiddenmessage"))

	if response.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}
