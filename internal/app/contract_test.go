package app_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/szerhusenBC/jwt-spring-security-demo/internal/testutil"
)

// The assertions below cover behaviour the original delegated to Spring
// Security, Spring MVC and Jackson, and which the port now owns itself.

// --- error envelope -------------------------------------------------------

func TestErrorEnvelope(t *testing.T) {
	application := testutil.NewApplication(t)
	userToken := application.GetTokenForLogin(t, "user", "password")

	tests := []struct {
		name    string
		request *http.Request
		status  int
		error   string
		message string
		path    string
	}{
		{
			name:    "wrong password",
			request: testutil.PostJSON("/api/authenticate", `{"password": "wrong", "username": "user"}`),
			status:  http.StatusUnauthorized, error: "Unauthorized",
			message: "Bad credentials", path: "/api/authenticate",
		},
		{
			name:    "unknown account",
			request: testutil.PostJSON("/api/authenticate", `{"password": "password", "username": "not_existing"}`),
			status:  http.StatusUnauthorized, error: "Unauthorized",
			message: "Bad credentials", path: "/api/authenticate",
		},
		{
			name:    "deactivated account by username",
			request: testutil.PostJSON("/api/authenticate", `{"password": "password", "username": "disabled"}`),
			status:  http.StatusUnauthorized, error: "Unauthorized",
			message: "User disabled was not activated", path: "/api/authenticate",
		},
		{
			name:    "deactivated account by email",
			request: testutil.PostJSON("/api/authenticate", `{"password": "password", "username": "disabled@user.com"}`),
			status:  http.StatusUnauthorized, error: "Unauthorized",
			message: "User disabled@user.com was not activated", path: "/api/authenticate",
		},
		{
			name:    "no credentials",
			request: testutil.Get("/api/person"),
			status:  http.StatusUnauthorized, error: "Unauthorized",
			message: "Full authentication is required to access this resource", path: "/api/person",
		},
		{
			name:    "unusable token",
			request: testutil.WithToken(testutil.Get("/api/person"), "garbage"),
			status:  http.StatusUnauthorized, error: "Unauthorized",
			message: "Full authentication is required to access this resource", path: "/api/person",
		},
		{
			name:    "insufficient authority",
			request: testutil.WithToken(testutil.Get("/api/hiddenmessage"), userToken),
			status:  http.StatusForbidden, error: "Forbidden",
			message: "Access is denied", path: "/api/hiddenmessage",
		},
		{
			name:    "unmapped path",
			request: testutil.WithToken(testutil.Get("/api/nope"), userToken),
			status:  http.StatusNotFound, error: "Not Found",
			message: "No message available", path: "/api/nope",
		},
		{
			name:    "wrong method",
			request: testutil.Get("/api/authenticate"),
			status:  http.StatusMethodNotAllowed, error: "Method Not Allowed",
			message: "Request method 'GET' not supported", path: "/api/authenticate",
		},
		{
			name:    "unsupported media type",
			request: postForm("/api/authenticate", `{"password": "password", "username": "user"}`),
			status:  http.StatusUnsupportedMediaType, error: "Unsupported Media Type",
			message: "Content type 'application/x-www-form-urlencoded;charset=UTF-8' not supported",
			path:    "/api/authenticate",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := application.Perform(t, test.request)

			if response.Code != test.status {
				t.Fatalf("status = %d, want %d (body %s)", response.Code, test.status, response.Body)
			}

			var body map[string]any
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatalf("decoding %s: %v", response.Body, err)
			}
			assertString(t, body, "error", test.error)
			assertString(t, body, "message", test.message)
			assertString(t, body, "path", test.path)
			if got := body["status"]; got != float64(test.status) {
				t.Errorf("status member = %v, want %d", got, test.status)
			}
			assertTimestamp(t, body)
		})
	}
}

func TestMethodNotAllowedCarriesAllow(t *testing.T) {
	application := testutil.NewApplication(t)

	response := application.Perform(t, testutil.Get("/api/authenticate"))

	if got := response.Header().Get("Allow"); got != "POST" {
		t.Errorf("Allow = %q, want %q", got, "POST")
	}
}

// timestampPattern is Jackson's StdDateFormat with a UTC offset.
var timestampPattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}\+0000$`)

func assertTimestamp(t *testing.T, body map[string]any) {
	t.Helper()

	timestamp, _ := body["timestamp"].(string)
	if !timestampPattern.MatchString(timestamp) {
		t.Errorf("timestamp = %q, want the form 2026-08-24T11:26:22.081+0000", timestamp)
	}
}

func assertString(t *testing.T, body map[string]any, member, want string) {
	t.Helper()

	if got, _ := body[member].(string); got != want {
		t.Errorf("%s = %q, want %q", member, got, want)
	}
}

func postForm(target, body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return request
}

// --- validation -----------------------------------------------------------

func TestValidationErrorBody(t *testing.T) {
	application := testutil.NewApplication(t)

	response := application.Perform(t, testutil.PostJSON("/api/authenticate",
		`{"password": "abc", "username": "user"}`))

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body %s)", response.Code, http.StatusBadRequest, response.Body)
	}

	want := "" +
		"  \"errors\" : [ {\n" +
		"    \"codes\" : [ \"Size.loginDto.password\", \"Size.password\", \"Size.java.lang.String\", \"Size\" ],\n" +
		"    \"arguments\" : [ {\n" +
		"      \"codes\" : [ \"loginDto.password\", \"password\" ],\n" +
		"      \"arguments\" : null,\n" +
		"      \"defaultMessage\" : \"password\",\n" +
		"      \"code\" : \"password\"\n" +
		"    }, 100, 4 ],\n" +
		"    \"defaultMessage\" : \"size must be between 4 and 100\",\n" +
		"    \"objectName\" : \"loginDto\",\n" +
		"    \"field\" : \"password\",\n" +
		"    \"rejectedValue\" : \"abc\",\n" +
		"    \"bindingFailure\" : false,\n" +
		"    \"code\" : \"Size\"\n" +
		"  } ],\n" +
		"  \"message\" : \"Validation failed for object='loginDto'. Error count: 1\",\n"
	if got := response.Body.String(); !strings.Contains(got, want) {
		t.Errorf("body =\n%s\ndoes not contain\n%s", got, want)
	}
}

func TestValidationRules(t *testing.T) {
	application := testutil.NewApplication(t)

	tests := []struct {
		name    string
		body    string
		message string
		field   string
	}{
		{name: "username absent", body: `{"password": "password"}`, message: "must not be null", field: "username"},
		{name: "password absent", body: `{"username": "user"}`, message: "must not be null", field: "password"},
		{name: "username too short", body: `{"password": "password", "username": ""}`, message: "size must be between 1 and 50", field: "username"},
		{name: "password too short", body: `{"password": "abc", "username": "user"}`, message: "size must be between 4 and 100", field: "password"},
		{name: "username too long", body: `{"password": "password", "username": "` + repeat("a", 51) + `"}`, message: "size must be between 1 and 50", field: "username"},
		{name: "password too long", body: `{"password": "` + repeat("a", 101) + `", "username": "user"}`, message: "size must be between 4 and 100", field: "password"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := application.Perform(t, testutil.PostJSON("/api/authenticate", test.body))

			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d (body %s)", response.Code, http.StatusBadRequest, response.Body)
			}
			body := response.Body.String()
			if !strings.Contains(body, `"defaultMessage" : "`+test.message+`"`) {
				t.Errorf("body %s does not report %q", body, test.message)
			}
			if !strings.Contains(body, `"field" : "`+test.field+`"`) {
				t.Errorf("body %s does not name field %q", body, test.field)
			}
		})
	}
}

func TestValidationCountsEveryViolation(t *testing.T) {
	application := testutil.NewApplication(t)

	response := application.Perform(t, testutil.PostJSON("/api/authenticate", `{}`))

	if !strings.Contains(response.Body.String(), "Error count: 2") {
		t.Errorf("body %s does not report two violations", response.Body)
	}
}

func repeat(s string, n int) string { return strings.Repeat(s, n) }

// --- security headers -----------------------------------------------------

func TestSecurityHeadersOnSecuredResponses(t *testing.T) {
	application := testutil.NewApplication(t)

	response := application.Perform(t, testutil.Get("/api/person"))

	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-XSS-Protection":       "1; mode=block",
		"Cache-Control":          "no-cache, no-store, max-age=0, must-revalidate",
		"Pragma":                 "no-cache",
		"Expires":                "0",
		// SAMEORIGIN, not the framework default DENY.
		"X-Frame-Options": "SAMEORIGIN",
	}
	for name, value := range want {
		if got := response.Header().Get(name); got != value {
			t.Errorf("%s = %q, want %q", name, got, value)
		}
	}
}

func TestNoSecurityHeadersOnIgnoredPaths(t *testing.T) {
	application := testutil.NewApplication(t)

	for _, path := range []string{"/", "/index.html", "/js/client.js", "/js/libs/jwt-decode.min.js"} {
		t.Run(path, func(t *testing.T) {
			response := application.Perform(t, testutil.Get(path))

			if got := response.Header().Get("X-Frame-Options"); got != "" {
				t.Errorf("%s carried X-Frame-Options %q; ignored paths never reach the security chain", path, got)
			}
		})
	}
}

func TestNoSessionCookieIsEverSet(t *testing.T) {
	application := testutil.NewApplication(t)

	response := application.Perform(t, testutil.PostJSON("/api/authenticate",
		`{"password": "password", "username": "user"}`))

	if got := response.Header().Values("Set-Cookie"); len(got) > 0 {
		t.Errorf("Set-Cookie = %v; the API is stateless", got)
	}
}

// --- CORS -----------------------------------------------------------------

func TestCorsPreflight(t *testing.T) {
	application := testutil.NewApplication(t)

	request := httptest.NewRequest(http.MethodOptions, "/api/person", nil)
	request.Header.Set("Origin", "http://example.com")
	request.Header.Set("Access-Control-Request-Method", "GET")

	response := application.Perform(t, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	// Credentials are allowed, so the concrete origin is echoed rather than "*".
	assertHeader(t, response, "Access-Control-Allow-Origin", "http://example.com")
	assertHeader(t, response, "Access-Control-Allow-Methods", "GET")
	assertHeader(t, response, "Access-Control-Allow-Credentials", "true")
	if got := response.Header().Values("Vary"); len(got) != 3 {
		t.Errorf("Vary = %v, want three entries", got)
	}
	if response.Body.Len() != 0 {
		t.Errorf("preflight body = %q, want empty", response.Body)
	}
	if got := response.Header().Get("X-Frame-Options"); got != "" {
		t.Errorf("preflight carried a security header %q; OPTIONS is ignored by the chain", got)
	}
}

func TestCorsPreflightEchoesRequestedHeaders(t *testing.T) {
	application := testutil.NewApplication(t)

	request := httptest.NewRequest(http.MethodOptions, "/api/authenticate", nil)
	request.Header.Set("Origin", "http://x.com")
	request.Header.Set("Access-Control-Request-Method", "POST")
	request.Header.Set("Access-Control-Request-Headers", "content-type")

	response := application.Perform(t, request)

	assertHeader(t, response, "Access-Control-Allow-Headers", "content-type")
	assertHeader(t, response, "Access-Control-Allow-Methods", "POST")
}

func TestCorsSimpleRequest(t *testing.T) {
	application := testutil.NewApplication(t)
	token := application.GetTokenForLogin(t, "user", "password")

	request := testutil.WithToken(testutil.Get("/api/person"), token)
	request.Header.Set("Origin", "http://example.com")

	response := application.Perform(t, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	assertHeader(t, response, "Access-Control-Allow-Origin", "http://example.com")
	assertHeader(t, response, "Access-Control-Allow-Credentials", "true")
	// A simple request is not a preflight, so no methods are advertised.
	assertHeader(t, response, "Access-Control-Allow-Methods", "")
}

// TestCorsIsScopedToTheApiPath pins the "/api/**" mapping: nothing else is
// decorated.
func TestCorsIsScopedToTheApiPath(t *testing.T) {
	application := testutil.NewApplication(t)

	request := testutil.Get("/")
	request.Header.Set("Origin", "http://example.com")

	response := application.Perform(t, request)

	assertHeader(t, response, "Access-Control-Allow-Origin", "")
}

func assertHeader(t *testing.T, response *httptest.ResponseRecorder, name, want string) {
	t.Helper()

	if got := response.Header().Get(name); got != want {
		t.Errorf("%s = %q, want %q", name, got, want)
	}
}

// --- password hashing -----------------------------------------------------

// TestSeededPasswordHashes checks the stored $2a$08$ hashes still verify. They
// are data, not code, so a port that silently switched hashing scheme or cost
// would lock every account out.
func TestSeededPasswordHashes(t *testing.T) {
	tests := []struct {
		hash     string
		password string
	}{
		{"$2a$08$lDnHPz7eUkSi6ao14Twuau08mzhWrL4kyZGGU5xfiGALO/Vxd5DOi", "admin"},
		{"$2a$08$UkVvwpULis18S19S5pZFn.YHPZt3oaqHZnDwqbCW9pft6uFtkXKDC", "password"},
	}

	for _, test := range tests {
		if err := bcrypt.CompareHashAndPassword([]byte(test.hash), []byte(test.password)); err != nil {
			t.Errorf("hash %s does not verify %q: %v", test.hash, test.password, err)
		}
		if err := bcrypt.CompareHashAndPassword([]byte(test.hash), []byte("wrong")); err == nil {
			t.Errorf("hash %s accepted the wrong password", test.hash)
		}
		if cost, err := bcrypt.Cost([]byte(test.hash)); err != nil || cost != 8 {
			t.Errorf("cost of %s = %d (%v), want 8", test.hash, cost, err)
		}
	}
}

// --- account lookup -------------------------------------------------------

// TestLoginByEmailOrUsername pins the branch that decides which column is
// searched, and the fact that the token's subject is always the database
// username rather than whatever the caller typed.
func TestLoginByEmailOrUsername(t *testing.T) {
	application := testutil.NewApplication(t)

	tests := []struct {
		name     string
		login    string
		password string
		subject  string
	}{
		{name: "by username", login: "user", password: "password", subject: "user"},
		{name: "by username, wrong case", login: "USER", password: "password", subject: "user"},
		{name: "by email", login: "enabled@user.com", password: "password", subject: "user"},
		{name: "by email, wrong case", login: "Enabled@User.Com", password: "password", subject: "user"},
		{name: "admin by email", login: "admin@admin.com", password: "admin", subject: "admin"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token := application.GetTokenForLogin(t, test.login, test.password)
			if token == "" {
				t.Fatalf("login %q was rejected", test.login)
			}
			if got := subjectOf(t, token); got != test.subject {
				t.Errorf("sub = %q, want %q", got, test.subject)
			}
		})
	}
}

// TestAuthClaimIsSortedButUserResponseIsNot pins the two different authority
// orderings the original produces for the same account.
func TestAuthClaimIsSortedButUserResponseIsNot(t *testing.T) {
	application := testutil.NewApplication(t)
	token := application.GetTokenForLogin(t, "admin", "admin")

	if got := authOf(t, token); got != "ROLE_ADMIN,ROLE_USER" {
		t.Errorf("auth claim = %q, want %q", got, "ROLE_ADMIN,ROLE_USER")
	}

	response := application.Perform(t, testutil.WithToken(testutil.Get("/api/user"), token))
	want := "  \"authorities\" : [ {\n    \"name\" : \"ROLE_USER\"\n  }, {\n    \"name\" : \"ROLE_ADMIN\"\n  } ]"
	if got := response.Body.String(); !strings.Contains(got, want) {
		t.Errorf("body =\n%s\ndoes not contain\n%s", got, want)
	}
}

// TestUserResponseHidesSensitiveMembers pins the three @JsonIgnore members.
func TestUserResponseHidesSensitiveMembers(t *testing.T) {
	application := testutil.NewApplication(t)
	token := application.GetTokenForLogin(t, "user", "password")

	response := application.Perform(t, testutil.WithToken(testutil.Get("/api/user"), token))

	for _, member := range []string{"id", "password", "activated", "$2a$"} {
		if strings.Contains(response.Body.String(), member) {
			t.Errorf("body %s leaks %q", response.Body, member)
		}
	}
}

func TestAuthenticateReturnsTheTokenInAHeaderToo(t *testing.T) {
	application := testutil.NewApplication(t)

	response := application.Perform(t, testutil.PostJSON("/api/authenticate",
		`{"password": "password", "username": "user"}`))

	var body struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding %s: %v", response.Body, err)
	}
	if got, want := response.Header().Get("Authorization"), "Bearer "+body.IDToken; got != want {
		t.Errorf("Authorization = %q, want %q", got, want)
	}
}

// TestRememberMeExtendsTheToken pins the two validity windows: 86400 seconds
// normally, 108000 with rememberMe.
func TestRememberMeExtendsTheToken(t *testing.T) {
	application := testutil.NewApplication(t)

	short := expiryOf(t, tokenFor(t, application, `{"password": "admin", "username": "admin"}`))
	long := expiryOf(t, tokenFor(t, application, `{"password": "admin", "username": "admin", "rememberMe": true}`))

	if delta := long - short; delta < 108000-86400-5 || delta > 108000-86400+5 {
		t.Errorf("rememberMe extended the token by %ds, want about %ds", delta, 108000-86400)
	}
}

func tokenFor(t *testing.T, application *testutil.Application, body string) string {
	t.Helper()

	response := application.Perform(t, testutil.PostJSON("/api/authenticate", body))
	var decoded struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("decoding %s: %v", response.Body, err)
	}
	return decoded.IDToken
}

func claimsOf(t *testing.T, token string) map[string]any {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token %q is not a three-part JWS", token)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decoding payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("decoding claims: %v", err)
	}
	return claims
}

func subjectOf(t *testing.T, token string) string {
	t.Helper()
	subject, _ := claimsOf(t, token)["sub"].(string)
	return subject
}

func authOf(t *testing.T, token string) string {
	t.Helper()
	auth, _ := claimsOf(t, token)["auth"].(string)
	return auth
}

func expiryOf(t *testing.T, token string) int64 {
	t.Helper()
	expiry, _ := claimsOf(t, token)["exp"].(float64)
	return int64(expiry)
}

// --- static resources -----------------------------------------------------

func TestStaticClientIsServed(t *testing.T) {
	application := testutil.NewApplication(t)

	// "/" and "/index.html" return the same bytes under different headers: the
	// first is rendered as the welcome-page view, the second is served straight
	// from the resource handler.
	tests := []struct {
		path        string
		contentType string
		contains    string
	}{
		{path: "/", contentType: "text/html;charset=UTF-8", contains: "<title>JWT Spring Security Demo</title>"},
		{path: "/index.html", contentType: "text/html", contains: "<title>JWT Spring Security Demo</title>"},
		{path: "/js/client.js", contentType: "application/javascript", contains: "/api/authenticate"},
		{path: "/js/libs/jwt-decode.min.js", contentType: "application/javascript", contains: "function"},
	}

	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			response := application.Perform(t, testutil.Get(test.path))

			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
			}
			assertHeader(t, response, "Content-Type", test.contentType)
			if !strings.Contains(response.Body.String(), test.contains) {
				t.Errorf("%s does not contain %q", test.path, test.contains)
			}
		})
	}
}

// TestContentLanguageIsOnlyOnTheWelcomePage pins the difference between the two
// routes to index.html.
func TestContentLanguageIsOnlyOnTheWelcomePage(t *testing.T) {
	application := testutil.NewApplication(t)

	assertHeader(t, application.Perform(t, testutil.Get("/")), "Content-Language", "en-US")
	assertHeader(t, application.Perform(t, testutil.Get("/index.html")), "Content-Language", "")
}

// --- logging --------------------------------------------------------------

// TestLogMessages pins the wording of the messages the security packages emit.
func TestLogMessages(t *testing.T) {
	application := testutil.NewApplication(t)

	application.Perform(t, testutil.Get("/api/person"))
	token := application.GetTokenForLogin(t, "user", "password")
	application.Perform(t, testutil.WithToken(testutil.Get("/api/person"), token))
	application.Perform(t, testutil.WithToken(testutil.Get("/api/person"), "aa.bb.cc"))

	logs := application.Logs.String()
	want := []string{
		"no valid JWT token found, uri: /api/person",
		"Authenticating user 'user'",
		"set Authentication to security context for 'user', uri: /api/person",
		"Invalid JWT signature.",
	}
	for _, message := range want {
		if !strings.Contains(logs, message) {
			t.Errorf("logs do not contain %q\n%s", message, logs)
		}
	}
}

// TestLogLevelsComeFromConfiguration pins that org.zerhusen.security logs at
// DEBUG, which application.yml selects.
func TestLogLevelsComeFromConfiguration(t *testing.T) {
	application := testutil.NewApplication(t)

	application.Perform(t, testutil.Get("/api/person"))

	logs := application.Logs.String()
	if !strings.Contains(logs, "DEBUG") {
		t.Errorf("no DEBUG output, so logging.level.org.zerhusen.security was not applied\n%s", logs)
	}
	if !strings.Contains(logs, "org.zerhusen.security.jwt.JWTFilter") {
		t.Errorf("logger names are not the original's\n%s", logs)
	}
}
