package rest_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/szerhusenBC/jwt-spring-security-demo/internal/testutil"
)

// AuthenticationRestControllerTest.

func TestSuccessfulAuthenticationWithUser(t *testing.T) {
	application := testutil.NewApplication(t)

	response := application.Perform(t, testutil.PostJSON("/api/authenticate",
		`{"password": "password", "username": "user"}`))

	assertAuthenticated(t, response.Code, response.Body.String())
}

func TestSuccessfulAuthenticationWithAdmin(t *testing.T) {
	application := testutil.NewApplication(t)

	response := application.Perform(t, testutil.PostJSON("/api/authenticate",
		`{"password": "admin", "username": "admin"}`))

	assertAuthenticated(t, response.Code, response.Body.String())
}

func TestUnsuccessfulAuthenticationWithDisabled(t *testing.T) {
	application := testutil.NewApplication(t)

	response := application.Perform(t, testutil.PostJSON("/api/authenticate",
		`{"password": "password", "username": "disabled"}`))

	assertNotAuthenticated(t, response.Code, response.Body.String())
}

func TestUnsuccessfulAuthenticationWithWrongPassword(t *testing.T) {
	application := testutil.NewApplication(t)

	response := application.Perform(t, testutil.PostJSON("/api/authenticate",
		`{"password": "wrong", "username": "user"}`))

	assertNotAuthenticated(t, response.Code, response.Body.String())
}

func TestUnsuccessfulAuthenticationWithNotExistingUser(t *testing.T) {
	application := testutil.NewApplication(t)

	response := application.Perform(t, testutil.PostJSON("/api/authenticate",
		`{"password": "password", "username": "not_existing"}`))

	assertNotAuthenticated(t, response.Code, response.Body.String())
}

func assertAuthenticated(t *testing.T, status int, body string) {
	t.Helper()

	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d (body %s)", status, http.StatusOK, body)
	}
	if !strings.Contains(body, "id_token") {
		t.Errorf("body %s does not contain id_token", body)
	}
}

func assertNotAuthenticated(t *testing.T, status int, body string) {
	t.Helper()

	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d (body %s)", status, http.StatusUnauthorized, body)
	}
	if strings.Contains(body, "id_token") {
		t.Errorf("body %s unexpectedly contains id_token", body)
	}
}
