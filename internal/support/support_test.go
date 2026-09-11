package support_test

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/szerhusenBC/jwt-spring-security-demo/internal/config"
	"github.com/szerhusenBC/jwt-spring-security-demo/internal/deps/springsecurity"
	"github.com/szerhusenBC/jwt-spring-security-demo/internal/logging"
	"github.com/szerhusenBC/jwt-spring-security-demo/internal/security"
	"github.com/szerhusenBC/jwt-spring-security-demo/internal/security/repository"
)

// Accessors and error types that Spring supplied in the original: the logging
// façade, the Ant path matcher's accessor, the YAML loader's file handling, the
// UsernameNotFoundException message, and the authority repository. None was
// reached by the ported suite.

func TestLoggerNameAndLevels(t *testing.T) {
	var out bytes.Buffer
	factory := logging.NewFactory(&out, logging.Info, map[string]logging.Level{
		"org.springframework.web": logging.Warn,
	})

	logger := factory.Logger("org.springframework.web.servlet")
	if logger.Name() != "org.springframework.web.servlet" {
		t.Errorf("Name() = %q", logger.Name())
	}

	// The prefix match puts this logger at WARN, so Warn emits and Info does not.
	logger.Warn("cache %s", "miss")
	logger.Error("boom %d", 7)
	if !strings.Contains(out.String(), "cache miss") {
		t.Errorf("Warn did not emit; got %q", out.String())
	}
	if !strings.Contains(out.String(), "boom 7") {
		t.Errorf("Error did not emit; got %q", out.String())
	}
	if !strings.Contains(out.String(), "WARN") || !strings.Contains(out.String(), "ERROR") {
		t.Errorf("level names missing from %q", out.String())
	}
}

func TestLoggerBelowLevelStaysSilent(t *testing.T) {
	var out bytes.Buffer
	factory := logging.NewFactory(&out, logging.Error, nil)
	logger := factory.Logger("quiet")

	logger.Warn("suppressed")
	if out.Len() != 0 {
		t.Errorf("expected no output, got %q", out.String())
	}
	logger.Error("emitted")
	if !strings.Contains(out.String(), "emitted") {
		t.Errorf("Error did not emit; got %q", out.String())
	}
}

func TestAntMatcherPatternAccessor(t *testing.T) {
	matcher := springsecurity.NewAntMatcher("/api/**")
	if matcher.Pattern() != "/api/**" {
		t.Errorf("Pattern() = %q, want %q", matcher.Pattern(), "/api/**")
	}
	if !matcher.Matches("/api/users/1") {
		t.Error("Matches(/api/users/1) = false, want true")
	}
	if matcher.Matches("/other") {
		t.Error("Matches(/other) = true, want false")
	}
}

func TestConfigLoadReadsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "application.yml")
	body := []byte("server:\n  port: 9999\njwt:\n  base64-secret: c2VjcmV0\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Port != 9999 {
		t.Errorf("Server.Port = %d, want 9999", cfg.Server.Port)
	}
}

func TestConfigLoadMissingFile(t *testing.T) {
	_, err := config.Load(filepath.Join(t.TempDir(), "absent.yml"))
	if err == nil {
		t.Fatal("Load of a missing file succeeded, want error")
	}
	if !strings.Contains(err.Error(), "absent.yml") {
		t.Errorf("error %q does not name the file", err)
	}
}

func TestUsernameNotFoundErrorMessage(t *testing.T) {
	err := &security.UsernameNotFoundError{Message: "user not found: admin"}
	if err.Error() != "user not found: admin" {
		t.Errorf("Error() = %q", err.Error())
	}
}

func TestAuthorityRepositoryFindAll(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("opening sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if _, err := db.Exec(`CREATE TABLE AUTHORITY (NAME TEXT PRIMARY KEY)`); err != nil {
		t.Fatalf("creating table: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO AUTHORITY (NAME) VALUES ('ROLE_USER'), ('ROLE_ADMIN')`); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	repo := repository.NewAuthorityRepository(db)
	authorities, err := repo.FindAll(context.Background())
	if err != nil {
		t.Fatalf("FindAll: %v", err)
	}

	// JpaRepository#findAll returns them ordered by the single-column key.
	var names []string
	for _, authority := range authorities {
		names = append(names, authority.Name)
	}
	if len(names) != 2 || names[0] != "ROLE_ADMIN" || names[1] != "ROLE_USER" {
		t.Errorf("FindAll() = %v, want [ROLE_ADMIN ROLE_USER]", names)
	}
}

func TestAuthorityRepositoryFindAllEmpty(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("opening sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`CREATE TABLE AUTHORITY (NAME TEXT PRIMARY KEY)`); err != nil {
		t.Fatalf("creating table: %v", err)
	}

	authorities, err := repository.NewAuthorityRepository(db).FindAll(context.Background())
	if err != nil {
		t.Fatalf("FindAll: %v", err)
	}
	if len(authorities) != 0 {
		t.Errorf("FindAll() = %v, want empty", authorities)
	}
}
