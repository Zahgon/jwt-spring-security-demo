package config

import (
	"bytes"
	"net/http"
)

// bufferedResponse holds a response back until it is known whether it will be
// written or replaced. It exists for one reason: an error raised on a path the
// security chain ignores is forwarded to /error, which the chain does not
// ignore, and the forward can discard the body that was about to be sent.
type bufferedResponse struct {
	target http.ResponseWriter
	header http.Header
	body   bytes.Buffer
	status int
}

func newBufferedResponse(target http.ResponseWriter) *bufferedResponse {
	return &bufferedResponse{target: target, header: http.Header{}, status: http.StatusOK}
}

func (b *bufferedResponse) Header() http.Header { return b.header }

func (b *bufferedResponse) WriteHeader(status int) { b.status = status }

func (b *bufferedResponse) Write(p []byte) (int, error) { return b.body.Write(p) }

// flush writes the buffered response through to the real writer.
func (b *bufferedResponse) flush() {
	b.copyHeader()
	b.target.WriteHeader(b.status)
	b.target.Write(b.body.Bytes())
}

// flushHeadersOnly writes the buffered headers under a different status and
// drops the body.
func (b *bufferedResponse) flushHeadersOnly(status int) {
	b.copyHeader()
	b.target.WriteHeader(status)
}

func (b *bufferedResponse) copyHeader() {
	target := b.target.Header()
	for name, values := range b.header {
		target[name] = values
	}
}
