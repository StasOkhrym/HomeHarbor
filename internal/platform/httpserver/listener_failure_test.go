package httpserver

import (
	"errors"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

func TestListenerFailureCancelsAndJoinsActiveHandlerBeforeTeardown(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(release) }) }
	defer finish()

	server := &http.Server{Handler: http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
		close(cancelled)
		<-release
	})}
	done := make(chan error, 1)
	go func() { done <- Serve(t.Context(), server, listener, time.Second) }()
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)

		client := &http.Client{Timeout: 5 * time.Second}

		response, err := client.Get("http://" + listener.Addr().String())
		if err == nil {
			_ = response.Body.Close()
		}
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("request did not enter handler")
	}

	// Break acceptance while the handler still owns application dependencies.
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case <-cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("listener failure did not cancel the active request")
	}

	select {
	case err := <-done:
		t.Fatalf("returned before the active handler released its dependencies: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	finish()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("listener failure lost after joining handler: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not join the released handler")
	}

	<-requestDone
}
