// Package testutil holds the shared test fixtures, the counterpart of the
// original's AbstractRestControllerTest and LogInUtils.
package testutil

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/szerhusenBC/jwt-spring-security-demo/internal/app"
	"github.com/szerhusenBC/jwt-spring-security-demo/internal/config"
	"github.com/szerhusenBC/jwt-spring-security-demo/internal/web"
)

// Application is a booted application under test, together with the log stream
// it wrote, so that tests can assert on log output as well as responses.
type Application struct {
	*app.Application
	Logs *SyncBuffer
}

// NewApplication boots the application against a freshly seeded in-memory
// database.
//
// Each call gets its own database and its own application, which is what makes
// the original's "clear the security context before each test" step
// unnecessary here: the authentication lives in the request context, so no
// state survives a request.
func NewApplication(t *testing.T) *Application {
	t.Helper()

	logs := &SyncBuffer{}
	application, err := app.New(Config(t), Resources(t), logs)
	if err != nil {
		t.Fatalf("booting application: %v", err)
	}
	t.Cleanup(func() {
		if err := application.Close(); err != nil {
			t.Errorf("closing application: %v", err)
		}
	})

	return &Application{Application: application, Logs: logs}
}

// Config loads the real application.yml, so tests exercise the shipped
// configuration rather than a copy of it.
func Config(t *testing.T) config.Config {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "config", "application.yml"))
	if err != nil {
		t.Fatalf("reading application.yml: %v", err)
	}
	cfg, err := config.Parse(raw)
	if err != nil {
		t.Fatalf("parsing application.yml: %v", err)
	}
	return cfg
}

// Resources loads the bundled resources from the working tree.
func Resources(t *testing.T) app.Resources {
	t.Helper()

	root := repoRoot(t)
	return app.Resources{
		Static:    os.DirFS(filepath.Join(root, "web", "static")),
		ImportSQL: readFile(t, filepath.Join(root, "resources", "import.sql")),
		Banner:    readFile(t, filepath.Join(root, "resources", "banner.txt")),
	}
}

// Perform sends a request through the application and returns the recorded
// response, standing in for MockMvc#perform.
func (a *Application) Perform(t *testing.T, request *http.Request) *httptest.ResponseRecorder {
	t.Helper()

	recorder := httptest.NewRecorder()
	a.Handler.ServeHTTP(recorder, request)
	return recorder
}

// Get builds a GET request with the JSON content type the original's tests set.
func Get(target string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, target, nil)
	request.Header.Set("Content-Type", web.ContentTypeJSON)
	return request
}

// PostJSON builds a POST request carrying a JSON body.
func PostJSON(target, body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	request.Header.Set("Content-Type", web.ContentTypeJSON)
	return request
}

// WithToken adds a bearer token to a request.
func WithToken(request *http.Request, token string) *http.Request {
	request.Header.Set("Authorization", "Bearer "+token)
	return request
}

// GetTokenForLogin posts the credentials to the authentication endpoint and
// returns the id_token from the response, the counterpart of
// LogInUtils.getTokenForLogin.
func (a *Application) GetTokenForLogin(t *testing.T, username, password string) string {
	t.Helper()

	response := a.Perform(t, PostJSON("/api/authenticate",
		`{"password": "`+password+`", "username": "`+username+`"}`))

	var authenticationResponse struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &authenticationResponse); err != nil {
		t.Fatalf("decoding authentication response %q: %v", response.Body.String(), err)
	}
	return authenticationResponse.IDToken
}

// SyncBuffer is a bytes.Buffer safe for the concurrent writes a log stream may
// see.
type SyncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *SyncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// String returns everything written so far.
func (b *SyncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

var _ io.Writer = (*SyncBuffer)(nil)

func readFile(t *testing.T, path string) string {
	t.Helper()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(content)
}

// repoRoot locates the module root from this file's own path, so tests can be
// run from any package directory.
func repoRoot(t *testing.T) string {
	t.Helper()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine the repository root")
	}
	return filepath.Dir(filepath.Dir(filepath.Dir(file)))
}
