package config

import (
	"net/http"
	"net/url"

	"github.com/szerhusenBC/jwt-spring-security-demo/internal/deps/springsecurity"
	"github.com/szerhusenBC/jwt-spring-security-demo/internal/security"
	"github.com/szerhusenBC/jwt-spring-security-demo/internal/security/jwt"
)

// Authorities the access rules refer to.
const (
	RoleUser  = "ROLE_USER"
	RoleAdmin = "ROLE_ADMIN"
)

// Messages Spring Security produces when a request is refused. Both reach the
// client verbatim.
const (
	fullAuthenticationRequired = "Full authentication is required to access this resource"
	accessDenied               = "Access is denied"
)

// WebSecurityConfig builds the security filter chain.
//
// It reproduces the two halves of the original's configuration: the paths the
// chain ignores entirely, and the ordered access rules applied to everything
// else. CSRF is disabled because the token is not carried in a cookie, and no
// session is ever created — the API is stateless, and nothing sets a cookie.
type WebSecurityConfig struct {
	tokenProvider            *jwt.TokenProvider
	jwtFilter                *jwt.Filter
	authenticationEntryPoint *security.AuthenticationEntryPoint
	accessDeniedHandler      *security.AccessDeniedHandler

	ignored []*springsecurity.AntMatcher
	rules   []accessRule
}

type accessRule struct {
	matcher   *springsecurity.AntMatcher
	authority string // empty means "any authenticated principal"
	permitAll bool
}

// NewWebSecurityConfig builds the configuration.
func NewWebSecurityConfig(
	tokenProvider *jwt.TokenProvider,
	jwtFilter *jwt.Filter,
	authenticationEntryPoint *security.AuthenticationEntryPoint,
	accessDeniedHandler *security.AccessDeniedHandler,
) *WebSecurityConfig {
	return &WebSecurityConfig{
		tokenProvider:            tokenProvider,
		jwtFilter:                jwtFilter,
		authenticationEntryPoint: authenticationEntryPoint,
		accessDeniedHandler:      accessDeniedHandler,

		// Paths the chain ignores. Responses for these carry none of the
		// security headers, because no part of the chain runs for them.
		//
		// The original also ignores "/h2-console/**"; the H2 web console is a
		// servlet shipped inside the H2 driver and has no counterpart here, so
		// the entry would guard nothing and is dropped with it.
		ignored: matchers(
			"/",
			"/*.html",
			"/favicon.ico",
			"/**/*.html",
			"/**/*.css",
			"/**/*.js",
		),

		// Access rules, applied in order; the first matching rule decides.
		rules: []accessRule{
			{matcher: springsecurity.NewAntMatcher("/api/authenticate"), permitAll: true},
			{matcher: springsecurity.NewAntMatcher("/api/person"), authority: RoleUser},
			{matcher: springsecurity.NewAntMatcher("/api/hiddenmessage"), authority: RoleAdmin},
			{matcher: springsecurity.NewAntMatcher("/**")},
		},
	}
}

// Handler wraps the application handler in the security filter chain.
func (c *WebSecurityConfig) Handler(application http.Handler) http.Handler {
	secured := c.jwtFilter.Handle(c.authorize(application))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c.isIgnored(r) {
			c.serveIgnored(w, r, application)
			return
		}
		writeSecurityHeaders(w)
		secured.ServeHTTP(w, r)
	})
}

// serveIgnored serves a path the chain skips, and models what the container
// does when such a path fails.
//
// An error status is not written straight back: the container forwards it to
// /error, and /error is *not* in the ignored list, so the forwarded request
// goes through the chain after all. For an anonymous caller that means the
// error body is never rendered — the response becomes a bare 401. It is why
// GET /missing.html answers 401 rather than 404 while a caller holding a token
// gets the 404 it asked for.
func (c *WebSecurityConfig) serveIgnored(w http.ResponseWriter, r *http.Request, application http.Handler) {
	buffered := newBufferedResponse(w)
	application.ServeHTTP(buffered, r)

	if buffered.status < http.StatusBadRequest || !c.errorDispatchRefuses(r) {
		buffered.flush()
		return
	}

	// Headers the handler set — notably Allow — survive the forward; the body
	// and its content type do not.
	buffered.header.Del("Content-Type")
	buffered.flushHeadersOnly(http.StatusUnauthorized)
}

// errorDispatchRefuses reports whether the chain would refuse the /error
// forward. OPTIONS is ignored for every path, /error included, so a failed
// preflight-less OPTIONS still renders its error.
func (c *WebSecurityConfig) errorDispatchRefuses(r *http.Request) bool {
	errorDispatch := r.Clone(r.Context())
	errorDispatch.URL = &url.URL{Path: "/error"}
	if c.isIgnored(errorDispatch) {
		return false
	}
	return !c.hasValidToken(r)
}

// hasValidToken reports whether the request carries a token the chain would
// accept. The forwarded request carries the same headers, so the same token is
// evaluated a second time.
func (c *WebSecurityConfig) hasValidToken(r *http.Request) bool {
	token := jwt.ResolveToken(r)
	return token != "" && c.tokenProvider.ValidateToken(token)
}

// isIgnored reports whether the chain skips this request. OPTIONS is ignored
// for every path, which is what lets the CORS filter answer preflights without
// them ever reaching an access rule.
func (c *WebSecurityConfig) isIgnored(r *http.Request) bool {
	if r.Method == http.MethodOptions {
		return true
	}
	for _, matcher := range c.ignored {
		if matcher.Matches(r.URL.Path) {
			return true
		}
	}
	return false
}

// authorize enforces the access rules, translating a refusal into 401 or 403.
//
// An unauthenticated request is refused with 401 rather than 403 even though it
// is the access rule that rejects it: Spring's ExceptionTranslationFilter sees
// that the principal is anonymous and hands the request to the authentication
// entry point instead of the access-denied handler.
func (c *WebSecurityConfig) authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rule, matched := c.ruleFor(r.URL.Path)
		if !matched || rule.permitAll {
			next.ServeHTTP(w, r)
			return
		}

		authentication := security.AuthenticationFrom(r.Context())
		if authentication == nil || !authentication.Authenticated {
			c.authenticationEntryPoint.Commence(w, r, fullAuthenticationRequired)
			return
		}
		if rule.authority != "" && !authentication.HasAuthority(rule.authority) {
			c.accessDeniedHandler.Handle(w, r, accessDenied)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (c *WebSecurityConfig) ruleFor(path string) (accessRule, bool) {
	for _, rule := range c.rules {
		if rule.matcher.Matches(path) {
			return rule, true
		}
	}
	return accessRule{}, false
}

// writeSecurityHeaders writes the header set Spring Security's HeaderWriterFilter
// contributes. X-Frame-Options is SAMEORIGIN rather than the framework default
// DENY, because the original relaxes it.
func writeSecurityHeaders(w http.ResponseWriter) {
	header := w.Header()
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-XSS-Protection", "1; mode=block")
	header.Set("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate")
	header.Set("Pragma", "no-cache")
	header.Set("Expires", "0")
	header.Set("X-Frame-Options", "SAMEORIGIN")
}

func matchers(patterns ...string) []*springsecurity.AntMatcher {
	compiled := make([]*springsecurity.AntMatcher, len(patterns))
	for i, pattern := range patterns {
		compiled[i] = springsecurity.NewAntMatcher(pattern)
	}
	return compiled
}
