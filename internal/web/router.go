package web

import (
	"net/http"
	"sort"
	"strings"
)

// Route is one request mapping, the counterpart of a @GetMapping or
// @PostMapping on a controller method.
type Route struct {
	// Method is the HTTP method the mapping accepts.
	Method string
	// Path is the exact request path the mapping answers.
	Path string
	// ConsumesJSON marks a mapping that reads a @RequestBody, and so rejects a
	// request whose body is not declared as JSON.
	ConsumesJSON bool
	// Handler serves the request.
	Handler http.HandlerFunc
}

// Router dispatches requests to routes and renders the three failures the
// dispatcher itself can produce: no mapping for the path, no mapping for the
// method, and a body in a media type the mapping cannot read.
type Router struct {
	routes    []Route
	fallback  http.Handler
	responder *Responder
}

// NewRouter builds a router. fallback handles paths no route claims — the
// static resource handler, which renders its own 404 when it has nothing to
// serve either.
func NewRouter(responder *Responder, fallback http.Handler, routes ...Route) *Router {
	return &Router{routes: routes, fallback: fallback, responder: responder}
}

func (router *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var allowed []string
	for _, route := range router.routes {
		if route.Path != r.URL.Path {
			continue
		}
		allowed = append(allowed, route.Method)
		if !methodMatches(route.Method, r.Method) {
			continue
		}
		if r.Method == http.MethodOptions {
			break
		}
		if route.ConsumesJSON && !isJSON(r) {
			router.responder.SendError(w, r, http.StatusUnsupportedMediaType,
				"Content type '"+requestContentType(r)+"' not supported")
			return
		}
		route.Handler(w, r)
		return
	}

	if len(allowed) > 0 {
		// A mapped path answers OPTIONS itself, advertising what it supports
		// rather than refusing the method.
		if r.Method == http.MethodOptions {
			WriteAllow(w, allowed)
			w.WriteHeader(http.StatusOK)
			return
		}
		sort.Strings(allowed)
		w.Header().Set("Allow", strings.Join(allowed, ","))
		router.responder.SendError(w, r, http.StatusMethodNotAllowed,
			"Request method '"+r.Method+"' not supported")
		return
	}

	router.fallback.ServeHTTP(w, r)
}

// methodMatches reports whether a mapping declared for routeMethod answers a
// request made with requestMethod.
//
// A GET mapping also answers HEAD: Spring's RequestMethodsRequestCondition
// falls back to the GET condition when nothing matches HEAD directly, so
// @GetMapping serves HEAD without declaring it. It is the same implication
// WriteAllow advertises, and the response body is suppressed by the transport
// rather than by the handler, exactly as the container does it.
func methodMatches(routeMethod, requestMethod string) bool {
	if routeMethod == requestMethod {
		return true
	}
	return requestMethod == http.MethodHead && routeMethod == http.MethodGet
}

// WriteAllow sets the Allow header of a default OPTIONS response. GET implies
// HEAD, and OPTIONS itself is always answered, so both are added to whatever
// the mapping declares.
func WriteAllow(w http.ResponseWriter, methods []string) {
	advertised := make([]string, 0, len(methods)+2)
	for _, method := range methods {
		advertised = append(advertised, method)
		if method == http.MethodGet {
			advertised = append(advertised, http.MethodHead)
		}
	}
	advertised = append(advertised, http.MethodOptions)
	w.Header().Set("Allow", strings.Join(advertised, ","))
}

// NotFound renders the dispatcher's 404. Spring has no message to report for a
// path that matched no handler, so the body carries the literal placeholder
// "No message available".
func (router *Router) NotFound(w http.ResponseWriter, r *http.Request) {
	router.responder.SendError(w, r, http.StatusNotFound, "No message available")
}

// MethodNotAllowed renders the dispatcher's 405 for a resource that exists but
// does not answer this method.
func (router *Router) MethodNotAllowed(w http.ResponseWriter, r *http.Request, allow string) {
	w.Header().Set("Allow", allow)
	router.responder.SendError(w, r, http.StatusMethodNotAllowed,
		"Request method '"+r.Method+"' not supported")
}
