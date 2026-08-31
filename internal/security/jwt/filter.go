package jwt

import (
	"net/http"
	"strings"

	"github.com/szerhusenBC/jwt-spring-security-demo/internal/logging"
	"github.com/szerhusenBC/jwt-spring-security-demo/internal/security"
)

// AuthorizationHeader is the request header a token travels in.
const AuthorizationHeader = "Authorization"

// bearerPrefix is matched exactly: a header that does not start with it is
// ignored rather than rejected, so the request simply proceeds unauthenticated.
const bearerPrefix = "Bearer "

// Filter installs a security principal on requests that carry a valid token.
// It is the counterpart of JWTFilter, which JWTConfigurer inserted ahead of
// Spring Security's username/password filter.
type Filter struct {
	tokenProvider *TokenProvider
	log           *logging.Logger
}

// NewFilter builds the filter.
func NewFilter(tokenProvider *TokenProvider, log *logging.Logger) *Filter {
	return &Filter{tokenProvider: tokenProvider, log: log}
}

// Handle wraps next, authenticating the request when a usable token is present.
func (f *Filter) Handle(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := ResolveToken(r)
		requestURI := r.URL.Path

		if token != "" && f.tokenProvider.ValidateToken(token) {
			authentication, err := f.tokenProvider.GetAuthentication(token)
			if err == nil {
				r = r.WithContext(security.WithAuthentication(r.Context(), authentication))
				f.log.Debug("set Authentication to security context for '%s', uri: %s", authentication.Name(), requestURI)
				next.ServeHTTP(w, r)
				return
			}
		}

		f.log.Debug("no valid JWT token found, uri: %s", requestURI)
		next.ServeHTTP(w, r)
	})
}

// ResolveToken returns the bearer token a request carries, or the empty string
// when it carries none in the expected form.
func ResolveToken(r *http.Request) string {
	bearerToken := r.Header.Get(AuthorizationHeader)
	if strings.HasPrefix(bearerToken, bearerPrefix) {
		return bearerToken[len(bearerPrefix):]
	}
	return ""
}
