package springsecurity_test

import (
	"testing"

	"github.com/szerhusenBC/jwt-spring-security-demo/internal/deps/springsecurity"
)

// The patterns below are the ones WebSecurityConfig actually uses.
func TestAntMatcher(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		want    bool
	}{
		{"/", "/", true},
		{"/", "/index.html", false},

		{"/*.html", "/index.html", true},
		{"/*.html", "/js/index.html", false},

		{"/favicon.ico", "/favicon.ico", true},

		// "**" spans zero or more whole segments, so these match at the root too.
		{"/**/*.html", "/index.html", true},
		{"/**/*.html", "/a/b/index.html", true},
		{"/**/*.html", "/index.htm", false},
		{"/**/*.js", "/js/client.js", true},
		{"/**/*.js", "/js/libs/jwt-decode.min.js", true},
		{"/**/*.css", "/css/site.css", true},
		{"/**/*.css", "/js/client.js", false},

		{"/api/**", "/api", true},
		{"/api/**", "/api/person", true},
		{"/api/**", "/api/a/b", true},
		{"/api/**", "/apix", false},
		{"/api/**", "/", false},

		{"/**", "/", true},
		{"/**", "/anything/at/all", true},

		{"/api/authenticate", "/api/authenticate", true},
		{"/api/authenticate", "/api/authenticate/x", false},
	}

	for _, test := range tests {
		matcher := springsecurity.NewAntMatcher(test.pattern)
		if got := matcher.Matches(test.path); got != test.want {
			t.Errorf("NewAntMatcher(%q).Matches(%q) = %v, want %v", test.pattern, test.path, got, test.want)
		}
	}
}
