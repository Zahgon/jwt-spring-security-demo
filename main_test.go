package main

import (
	"errors"
	"net"
	"net/http"
	"syscall"
	"testing"
	"time"
)

// TestRunServesThenShutsDownCleanly covers run(), the boot path main() calls.
//
// It is the Go equivalent of Spring Boot starting the embedded container and
// stopping it on SIGTERM: run() must serve real requests and then return nil
// when the signal arrives, rather than reporting the shutdown as a failure.
func TestRunServesThenShutsDownCleanly(t *testing.T) {
	done := make(chan error, 1)
	go func() { done <- run() }()

	addr := net.JoinHostPort("127.0.0.1", "8080")
	if !waitForListener(t, addr) {
		t.Fatal("run() never started listening on " + addr)
	}

	// The server is up and answering: the static client is served at the root.
	response, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatalf("requesting the running server: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode >= 500 {
		t.Errorf("GET / = %d, want a non-server-error status", response.StatusCode)
	}

	// SIGTERM is one of the two signals run() installs; it must shut down
	// gracefully and report success.
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("signalling: %v", err)
	}

	select {
	case err := <-done:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("run() = %v, want nil after SIGTERM", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("run() did not return within 15s of SIGTERM")
	}
}

func waitForListener(t *testing.T, addr string) bool {
	t.Helper()
	for i := 0; i < 100; i++ {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}
