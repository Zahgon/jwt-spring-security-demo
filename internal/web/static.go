package web

import (
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

// StaticHandler serves the bundled single-page client, which Spring Boot serves
// from the classpath's static/ directory.
//
// "/" and "/index.html" return the same bytes but not the same headers,
// because Spring reaches them by two different routes. "/" is the welcome page
// Spring Boot registers when static/index.html exists, and it is rendered as a
// view — so it picks up the negotiated charset and the locale resolver's
// Content-Language. "/index.html" is served by the resource handler straight
// from the classpath, with only the media type the container maps the
// extension to.
type StaticHandler struct {
	files            fs.FS
	notFound         http.HandlerFunc
	methodNotAllowed func(w http.ResponseWriter, r *http.Request, allow string)
	// modTime stamps Last-Modified. The files are embedded in the binary and so
	// have no meaningful timestamp of their own; the process start time stands
	// in for the deployment time a classpath resource would report.
	modTime time.Time
}

// NewStaticHandler builds a handler over files. It delegates to notFound for
// paths it has nothing for, and to methodNotAllowed for a resource that exists
// but was asked for with a method it does not serve.
func NewStaticHandler(files fs.FS, notFound http.HandlerFunc, methodNotAllowed func(http.ResponseWriter, *http.Request, string)) *StaticHandler {
	return &StaticHandler{
		files:            files,
		notFound:         notFound,
		methodNotAllowed: methodNotAllowed,
		modTime:          time.Now(),
	}
}

// staticAllow is the method set a static resource answers, in the spelling the
// resource handler uses on a 405.
const staticAllow = "GET, HEAD"

func (h *StaticHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	welcome := r.URL.Path == "/"
	name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
	if name == "" || name == "." {
		name = welcomePage
	}

	file, err := h.files.Open(name)
	if err != nil {
		h.notFound(w, r)
		return
	}
	defer file.Close()

	// The resource exists, so a method it does not serve is a 405 rather than
	// a 404, and OPTIONS is answered with what it does serve.
	if r.Method == http.MethodOptions {
		WriteAllow(w, []string{http.MethodGet})
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		h.methodNotAllowed(w, r, staticAllow)
		return
	}

	content, ok := file.(interface {
		Read([]byte) (int, error)
		Seek(int64, int) (int64, error)
	})
	if !ok {
		h.notFound(w, r)
		return
	}

	if welcome {
		// Rendered as a view: charset negotiated, locale resolved.
		w.Header().Set("Content-Type", "text/html;charset=UTF-8")
		w.Header().Set("Content-Language", "en-US")
	} else if contentType := contentTypeFor(name); contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	http.ServeContent(w, r, name, h.modTime, content)
}

// welcomePage is the resource "/" resolves to.
const welcomePage = "index.html"

// contentTypeFor maps the extensions the bundled client uses. Spring resolves
// these through the servlet container's mime mappings, which supply no charset.
func contentTypeFor(name string) string {
	switch path.Ext(name) {
	case ".html":
		return "text/html"
	case ".js":
		return "application/javascript"
	case ".css":
		return "text/css"
	case ".ico":
		return "image/x-icon"
	case ".png":
		return "image/png"
	default:
		return ""
	}
}
