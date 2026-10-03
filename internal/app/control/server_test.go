package control

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestHTTPComponentJoinsActiveRequestOnShutdown(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	entered := make(chan struct{})
	release := make(chan struct{})
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		w.WriteHeader(http.StatusNoContent)
	})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- serveHTTP(ctx, server, listener) }()
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)

		client := &http.Client{Timeout: 3 * time.Second}

		response, err := client.Get("http://" + listener.Addr().String())
		if err == nil {
			_ = response.Body.Close()
		}
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("request did not start")
	}

	cancel()
	select {
	case err := <-done:
		t.Fatalf("returned before active request stopped: %v", err)
	default:
	}

	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not join shutdown")
	}

	<-requestDone
}

func TestHTTPComponentReturnsListenerFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	_ = listener.Close()

	if err := serveHTTP(
		context.Background(),
		&http.Server{},
		listener,
	); !errors.Is(
		err,
		net.ErrClosed,
	) {
		t.Fatalf("error = %v, want closed listener", err)
	}
}

func TestServerDoesNotCloseStoresBeforeHandlersExit(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	entered, cancelled, release, closed := make(
		chan struct{},
	), make(
		chan struct{},
	), make(
		chan struct{},
	), make(
		chan struct{},
	)
	server := &http.Server{Handler: http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
		close(cancelled)
		<-release
	})}
	stores := &runtimeStores{closers: []func(){func() { close(closed) }}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { defer stores.close(); done <- serveHTTP(ctx, server, listener, -time.Nanosecond) }()
	go func() {
		response, err := http.Get("http://" + listener.Addr().String())
		if err == nil {
			_ = response.Body.Close()
		}
	}()
	<-entered
	cancel()
	<-cancelled
	select {
	case <-closed:
		close(release)
		<-done

		t.Fatal("stores closed under active handler")
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler shutdown not joined")
	}

	<-closed
}
