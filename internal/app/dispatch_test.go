package app_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/szerhusenBC/jwt-spring-security-demo/internal/testutil"
)

// The behaviours below were all found by comparing the port against the running
// original, and each one was wrong in the first port.

// TestDefaultOptionsHandling pins the dispatcher's own answer to OPTIONS: a
// mapped path reports what it supports rather than refusing the method, with
// GET implying HEAD.
func TestDefaultOptionsHandling(t *testing.T) {
	application := testutil.NewApplication(t)

	tests := map[string]string{
		"/api/authenticate":  "POST,OPTIONS",
		"/api/person":        "GET,HEAD,OPTIONS",
		"/api/user":          "GET,HEAD,OPTIONS",
		"/api/hiddenmessage": "GET,HEAD,OPTIONS",
		"/":                  "GET,HEAD,OPTIONS",
		"/index.html":        "GET,HEAD,OPTIONS",
		"/js/client.js":      "GET,HEAD,OPTIONS",
	}

	for path, allow := range tests {
		t.Run(path, func(t *testing.T) {
			response := application.Perform(t, httptest.NewRequest(http.MethodOptions, path, nil))

			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
			}
			if got := response.Header().Get("Allow"); got != allow {
				t.Errorf("Allow = %q, want %q", got, allow)
			}
			if response.Body.Len() != 0 {
				t.Errorf("body = %q, want empty", response.Body)
			}
		})
	}
}

func TestOptionsOnAnUnmappedPathIsNotFound(t *testing.T) {
	application := testutil.NewApplication(t)

	response := application.Perform(t, httptest.NewRequest(http.MethodOptions, "/nothere", nil))

	// OPTIONS is ignored for every path, /error included, so the 404 renders
	// rather than turning into a 401.
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d (body %s)", response.Code, http.StatusNotFound, response.Body)
	}
	if !strings.Contains(response.Body.String(), "No message available") {
		t.Errorf("body %s is not the standard error envelope", response.Body)
	}
}

// TestPreflightWithoutAConfigurationIsRejected pins that a preflight for a path
// outside /api/** is refused outright rather than passed down the chain.
func TestPreflightWithoutAConfigurationIsRejected(t *testing.T) {
	application := testutil.NewApplication(t)

	for _, path := range []string{"/index.html", "/nothere"} {
		t.Run(path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodOptions, path, nil)
			request.Header.Set("Origin", "http://e.com")
			request.Header.Set("Access-Control-Request-Method", "GET")

			response := application.Perform(t, request)

			if response.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
			}
			if got := response.Body.String(); got != "Invalid CORS request" {
				t.Errorf("body = %q, want %q", got, "Invalid CORS request")
			}
			if got := response.Header().Get("Content-Type"); got != "" {
				t.Errorf("Content-Type = %q, want none", got)
			}
			if got := response.Header().Get("Allow"); got != "GET, HEAD, POST, PUT, DELETE, TRACE, OPTIONS, PATCH" {
				t.Errorf("Allow = %q", got)
			}
		})
	}
}

// TestErrorsOnIgnoredPathsAreRefusedAnonymously pins the /error forward: a path
// the security chain ignores still ends up filtered when it fails, because
// /error is not ignored. An anonymous caller gets a bare 401 instead of the
// error it caused.
func TestErrorsOnIgnoredPathsAreRefusedAnonymously(t *testing.T) {
	application := testutil.NewApplication(t)

	tests := []struct {
		name    string
		request *http.Request
		allow   string
	}{
		{name: "missing html", request: httptest.NewRequest(http.MethodGet, "/missing.html", nil)},
		{name: "missing js", request: httptest.NewRequest(http.MethodGet, "/missing.js", nil)},
		{name: "method not served", request: httptest.NewRequest(http.MethodPost, "/js/client.js", nil), allow: "GET, HEAD"},
		{name: "method not served on the welcome page", request: httptest.NewRequest(http.MethodPost, "/", nil), allow: "GET, HEAD"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := application.Perform(t, test.request)

			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d (body %s)", response.Code, http.StatusUnauthorized, response.Body)
			}
			if response.Body.Len() != 0 {
				t.Errorf("body = %q, want empty", response.Body)
			}
			if got := response.Header().Get("Content-Type"); got != "" {
				t.Errorf("Content-Type = %q, want none", got)
			}
			// Headers the handler set survive the forward.
			if got := response.Header().Get("Allow"); got != test.allow {
				t.Errorf("Allow = %q, want %q", got, test.allow)
			}
		})
	}
}

// TestErrorsOnIgnoredPathsRenderForAuthenticatedCallers is the other half: with
// a token the forward passes, and the caller sees the error it caused.
func TestErrorsOnIgnoredPathsRenderForAuthenticatedCallers(t *testing.T) {
	application := testutil.NewApplication(t)
	token := application.GetTokenForLogin(t, "user", "password")

	t.Run("missing resource", func(t *testing.T) {
		response := application.Perform(t, testutil.WithToken(
			httptest.NewRequest(http.MethodGet, "/missing.html", nil), token))

		if response.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want %d", response.Code, http.StatusNotFound)
		}
		if !strings.Contains(response.Body.String(), "No message available") {
			t.Errorf("body %s is not the standard error envelope", response.Body)
		}
	})

	t.Run("method not served", func(t *testing.T) {
		response := application.Perform(t, testutil.WithToken(
			httptest.NewRequest(http.MethodPost, "/js/client.js", nil), token))

		if response.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status = %d, want %d", response.Code, http.StatusMethodNotAllowed)
		}
		if got := response.Header().Get("Allow"); got != "GET, HEAD" {
			t.Errorf("Allow = %q, want %q", got, "GET, HEAD")
		}
		if !strings.Contains(response.Body.String(), "Request method 'POST' not supported") {
			t.Errorf("body %s does not name the method", response.Body)
		}
	})
}

// TestUnmappedNonApiPathIsRefusedWithABody separates the two 401 routes: a path
// the chain does *not* ignore is refused by the chain itself, with the full
// error envelope.
func TestUnmappedNonApiPathIsRefusedWithABody(t *testing.T) {
	application := testutil.NewApplication(t)

	response := application.Perform(t, testutil.Get("/nothere.txt"))

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
	if !strings.Contains(response.Body.String(), "Full authentication is required to access this resource") {
		t.Errorf("body %s is not the entry point's refusal", response.Body)
	}
}

func TestHeadIsServedForStaticResources(t *testing.T) {
	application := testutil.NewApplication(t)

	response := application.Perform(t, httptest.NewRequest(http.MethodHead, "/js/client.js", nil))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	assertHeader(t, response, "Content-Type", "application/javascript")
}

// TestHeadIsServedByGetMappings pins that a GET mapping also answers HEAD.
// Spring's RequestMethodsRequestCondition falls back to the GET condition when
// nothing matches HEAD directly, so a @GetMapping serves HEAD without ever
// declaring it. It is the same implication the default OPTIONS answer above
// advertises; the port had advertised HEAD and then refused it with 405.
func TestHeadIsServedByGetMappings(t *testing.T) {
	application := testutil.NewApplication(t)
	token := application.GetTokenForLogin(t, "admin", "admin")

	for _, path := range []string{"/api/user", "/api/person", "/api/hiddenmessage"} {
		t.Run(path, func(t *testing.T) {
			get := application.Perform(t, testutil.WithToken(
				httptest.NewRequest(http.MethodGet, path, nil), token))
			head := application.Perform(t, testutil.WithToken(
				httptest.NewRequest(http.MethodHead, path, nil), token))

			if head.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d (GET answers %d)", head.Code, http.StatusOK, get.Code)
			}
			if got, want := head.Header().Get("Content-Type"), get.Header().Get("Content-Type"); got != want {
				t.Errorf("Content-Type = %q, want %q, the GET content type", got, want)
			}
		})
	}
}

// TestHeadOnAPostMappingIsStillRefused is the other half of the fallback: it
// reaches a GET mapping, and nothing else.
func TestHeadOnAPostMappingIsStillRefused(t *testing.T) {
	application := testutil.NewApplication(t)

	response := application.Perform(t, httptest.NewRequest(http.MethodHead, "/api/authenticate", nil))

	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusMethodNotAllowed)
	}
	if got := response.Header().Get("Allow"); got != "POST" {
		t.Errorf("Allow = %q, want %q", got, "POST")
	}
}

// TestHeadSendsNoBodyOverTheWire covers the half a ResponseRecorder cannot
// show. The handler writes its body for HEAD as it does for GET; discarding it
// while keeping the length it would have had is the transport's job, in Go as
// in the servlet container. So this one runs against a real server and reads
// the real response.
func TestHeadSendsNoBodyOverTheWire(t *testing.T) {
	application := testutil.NewApplication(t)
	token := application.GetTokenForLogin(t, "admin", "admin")

	server := httptest.NewServer(application.Handler)
	defer server.Close()

	perform := func(method string) (*http.Response, []byte) {
		t.Helper()

		request, err := http.NewRequest(method, server.URL+"/api/user", nil)
		if err != nil {
			t.Fatalf("building %s: %v", method, err)
		}
		request.Header.Set("Authorization", "Bearer "+token)

		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatalf("%s: %v", method, err)
		}
		defer response.Body.Close()

		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatalf("reading the %s body: %v", method, err)
		}
		return response, body
	}

	getResponse, getBody := perform(http.MethodGet)
	headResponse, headBody := perform(http.MethodHead)

	if headResponse.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", headResponse.StatusCode, http.StatusOK)
	}
	if len(headBody) != 0 {
		t.Errorf("body = %q, want empty", headBody)
	}
	if headResponse.ContentLength != int64(len(getBody)) {
		t.Errorf("Content-Length = %d, want %d, the length of the GET body",
			headResponse.ContentLength, len(getBody))
	}
	if got, want := headResponse.Header.Get("Content-Type"), getResponse.Header.Get("Content-Type"); got != want {
		t.Errorf("Content-Type = %q, want %q", got, want)
	}
}
