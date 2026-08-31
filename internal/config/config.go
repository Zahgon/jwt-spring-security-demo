// Package config loads application.yml, the same configuration file the
// original Spring Boot application reads, and turns the security-relevant keys
// into values the rest of the application can use.
//
// Only the keys that carry behaviour survive the migration. The Spring-specific
// blocks — spring.jackson, spring.jpa, spring.h2, spring.devtools — selected
// framework features rather than describing them, and the features they
// selected are now either implemented directly (indented JSON, schema creation)
// or out of scope (devtools restart, the H2 console).
package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/szerhusenBC/jwt-spring-security-demo/internal/logging"
)

// Config is the parsed application configuration.
type Config struct {
	Server  Server
	JWT     JWT
	Logging Logging
}

// Server holds the HTTP listener settings.
type Server struct {
	Port        int
	ContextPath string
}

// JWT holds the token settings. Secret is the decoded key material, not the
// base64 text: jjwt's Keys.hmacShaKeyFor is given the decoded bytes, and
// signing with the base64 string itself would produce tokens the original
// rejects.
type JWT struct {
	Header                     string
	Secret                     []byte
	TokenValidity              time.Duration
	TokenValidityForRememberMe time.Duration
}

// Logging holds the logger levels.
type Logging struct {
	Root   logging.Level
	Levels map[string]logging.Level
}

type file struct {
	Server struct {
		Port        int    `yaml:"port"`
		ContextPath string `yaml:"context-path"`
	} `yaml:"server"`
	JWT struct {
		Header                              string `yaml:"header"`
		Base64Secret                        string `yaml:"base64-secret"`
		TokenValidityInSeconds              int64  `yaml:"token-validity-in-seconds"`
		TokenValidityInSecondsForRememberMe int64  `yaml:"token-validity-in-seconds-for-remember-me"`
	} `yaml:"jwt"`
	Logging struct {
		Level map[string]string `yaml:"level"`
	} `yaml:"logging"`
}

// Load reads and validates the configuration file at path.
func Load(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("reading %s: %w", path, err)
	}
	return Parse(raw)
}

// Parse builds a Config from the contents of an application.yml.
func Parse(raw []byte) (Config, error) {
	var parsed file
	if err := yaml.Unmarshal(raw, &parsed); err != nil {
		return Config{}, fmt.Errorf("parsing application.yml: %w", err)
	}

	secret, err := base64.StdEncoding.DecodeString(parsed.JWT.Base64Secret)
	if err != nil {
		return Config{}, fmt.Errorf("decoding jwt.base64-secret: %w", err)
	}
	if len(secret) == 0 {
		return Config{}, fmt.Errorf("jwt.base64-secret is required")
	}

	cfg := Config{
		Server: Server{Port: parsed.Server.Port, ContextPath: parsed.Server.ContextPath},
		JWT: JWT{
			Header:                     parsed.JWT.Header,
			Secret:                     secret,
			TokenValidity:              time.Duration(parsed.JWT.TokenValidityInSeconds) * time.Second,
			TokenValidityForRememberMe: time.Duration(parsed.JWT.TokenValidityInSecondsForRememberMe) * time.Second,
		},
		Logging: Logging{Root: logging.Info, Levels: map[string]logging.Level{}},
	}
	if cfg.Server.Port == 0 {
		cfg.Server.Port = 8080
	}
	if cfg.Server.ContextPath == "" {
		cfg.Server.ContextPath = "/"
	}
	for name, level := range parsed.Logging.Level {
		if name == "root" {
			cfg.Logging.Root = logging.ParseLevel(level)
			continue
		}
		cfg.Logging.Levels[name] = logging.ParseLevel(level)
	}
	return cfg, nil
}
