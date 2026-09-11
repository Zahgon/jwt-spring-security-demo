// Package springsecurity holds the pieces of Spring Security whose behaviour
// the original's configuration selects and whose effects are visible on the
// wire.
package springsecurity

import (
	"regexp"
	"strings"
)

// AntMatcher matches request paths against an Ant-style pattern, the notation
// WebSecurityConfig uses in antMatchers(...) and web.ignoring().
//
// This covers the operators the original's patterns actually use:
//
//	?   one character, not '/'
//	*   zero or more characters within one path segment
//	**  zero or more whole path segments
//
// The full AntPathMatcher also supports URI template variables and
// pattern comparison for handler selection; neither appears in this
// application's configuration.
type AntMatcher struct {
	pattern string
	re      *regexp.Regexp
}

// NewAntMatcher compiles an Ant pattern. It panics on a pattern that cannot be
// compiled, which makes a bad route table a startup failure rather than a
// silent mismatch.
func NewAntMatcher(pattern string) *AntMatcher {
	return &AntMatcher{pattern: pattern, re: regexp.MustCompile("^" + translate(pattern) + "$")}
}

// Pattern returns the pattern the matcher was built from.
func (m *AntMatcher) Pattern() string { return m.pattern }

// Matches reports whether path matches the pattern.
func (m *AntMatcher) Matches(path string) bool { return m.re.MatchString(path) }

func translate(pattern string) string {
	var out strings.Builder
	for i := 0; i < len(pattern); i++ {
		// "/**" is handled as a unit: it stands for zero or more whole
		// segments, so the slash in front of it has to be optional too. That is
		// what lets "/**/*.html" match "/index.html" and "/api/**" match
		// "/api" itself.
		if strings.HasPrefix(pattern[i:], "/**") {
			out.WriteString("(?:/.*)?")
			i += 2
			continue
		}
		switch c := pattern[i]; c {
		case '?':
			out.WriteString("[^/]")
		case '*':
			if strings.HasPrefix(pattern[i:], "**") {
				out.WriteString(".*")
				i++
				continue
			}
			out.WriteString("[^/]*")
		default:
			out.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	return out.String()
}
