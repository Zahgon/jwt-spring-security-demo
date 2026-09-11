package rest_test

import (
	"net/http"
	"testing"

	"github.com/szerhusenBC/jwt-spring-security-demo/internal/testutil"
)

// UserRestControllerTest.

func TestGetActualUserForUserWithToken(t *testing.T) {
	application := testutil.NewApplication(t)
	token := application.GetTokenForLogin(t, "user", "password")

	response := application.Perform(t, testutil.WithToken(testutil.Get("/api/user"), token))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body %s)", response.Code, http.StatusOK, response.Body)
	}
	want := "{\n" +
		"  \"username\" : \"user\",\n" +
		"  \"firstname\" : \"user\",\n" +
		"  \"lastname\" : \"user\",\n" +
		"  \"email\" : \"enabled@user.com\",\n" +
		"  \"authorities\" : [ {\n" +
		"    \"name\" : \"ROLE_USER\"\n" +
		"  } ]\n" +
		"}"
	if got := response.Body.String(); got != want {
		t.Errorf("body =\n%s\nwant\n%s", got, want)
	}
}

func TestGetActualUserForUserWithoutToken(t *testing.T) {
	application := testutil.NewApplication(t)

	response := application.Perform(t, testutil.Get("/api/user"))

	if response.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}
