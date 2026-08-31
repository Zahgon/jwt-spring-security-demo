package config

import (
	"net/http"
	"strings"

	"github.com/szerhusenBC/jwt-spring-security-demo/internal/deps/springsecurity"
)

// CorsFilter answers CORS preflights and decorates cross-origin responses.
//
// The original registers a CorsFilter bean whose configuration is bound to the
// path pattern "/api/**" with credentials allowed and origins, headers and
// methods all "*". Because credentials are allowed, the response must name a
// concrete origin rather than "*", so the request's own Origin is echoed back;
// likewise the allowed methods and headers echo what the preflight asked for.
//
// The filter is registered outside the security chain, so it also handles the
// OPTIONS requests that the chain is configured to ignore. A preflight for a
// path the configuration does not cover is refused outright rather than passed
// on, which is what makes a cross-origin call to anything but /api/** fail.
type CorsFilter struct {
	pattern *springsecurity.AntMatcher
}

// NewCorsFilter builds the filter with the original's path mapping.
func NewCorsFilter() *CorsFilter {
	return &CorsFilter{pattern: springsecurity.NewAntMatcher("/api/**")}
}

// Handle wraps next with CORS processing.
func (f *CorsFilter) Handle(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			next.ServeHTTP(w, r)
			return
		}

		if !f.pattern.Matches(r.URL.Path) {
			if isPreflight(r) {
				rejectRequest(w)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		header := w.Header()
		header.Add("Vary", "Origin")
		header.Add("Vary", "Access-Control-Request-Method")
		header.Add("Vary", "Access-Control-Request-Headers")
		header.Set("Access-Control-Allow-Origin", origin)

		if isPreflight(r) {
			header.Set("Access-Control-Allow-Methods", r.Header.Get("Access-Control-Request-Method"))
			if requestHeaders := r.Header.Get("Access-Control-Request-Headers"); requestHeaders != "" {
				header.Set("Access-Control-Allow-Headers", normalizeHeaderList(requestHeaders))
			}
			header.Set("Access-Control-Allow-Credentials", "true")
			w.WriteHeader(http.StatusOK)
			return
		}

		header.Set("Access-Control-Allow-Credentials", "true")
		next.ServeHTTP(w, r)
	})
}

// isPreflight reports whether the request is a CORS preflight: an OPTIONS
// request that names the method it is asking about.
func isPreflight(r *http.Request) bool {
	return r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != ""
}

// rejectRequest refuses a preflight that no CORS configuration covers. The
// body is plain text with no content type, and the Allow header is the
// container's default OPTIONS response, listing every method the dispatcher
// implements.
func rejectRequest(w http.ResponseWriter) {
	header := w.Header()
	header.Set("Allow", "GET, HEAD, POST, PUT, DELETE, TRACE, OPTIONS, PATCH")
	// The rejection carries no content type at all. Assigning nil suppresses
	// the one net/http would otherwise sniff from the body.
	header["Content-Type"] = nil
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte("Invalid CORS request"))
}

// normalizeHeaderList trims the comma-separated header names a preflight asks
// for, which is how Spring echoes them back when allowedHeaders is "*".
func normalizeHeaderList(value string) string {
	names := strings.Split(value, ",")
	for i, name := range names {
		names[i] = strings.TrimSpace(name)
	}
	return strings.Join(names, ",")
}
