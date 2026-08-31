package rest_test

import (
	"net/http"
	"testing"

	"github.com/szerhusenBC/jwt-spring-security-demo/internal/testutil"
)

// PersonRestControllerTest.

func TestGetPersonForUser(t *testing.T) {
	application := testutil.NewApplication(t)
	token := application.GetTokenForLogin(t, "user", "password")

	assertSuccessfulPersonRequest(t, application, token)
}

func TestGetPersonForAdmin(t *testing.T) {
	application := testutil.NewApplication(t)
	token := application.GetTokenForLogin(t, "admin", "admin")

	assertSuccessfulPersonRequest(t, application, token)
}

func TestGetPersonForAnonymous(t *testing.T) {
	application := testutil.NewApplication(t)

	response := application.Perform(t, testutil.Get("/api/person"))

	if response.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}

func assertSuccessfulPersonRequest(t *testing.T, application *testutil.Application, token string) {
	t.Helper()

	response := application.Perform(t, testutil.WithToken(testutil.Get("/api/person"), token))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body %s)", response.Code, http.StatusOK, response.Body)
	}
	want := "{\n  \"name\" : \"John Doe\",\n  \"email\" : \"john.doe@test.org\"\n}"
	if got := response.Body.String(); got != want {
		t.Errorf("body =\n%s\nwant\n%s", got, want)
	}
}
