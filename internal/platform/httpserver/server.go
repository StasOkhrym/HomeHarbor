// Package httpserver joins accepted handlers before resource teardown.
package httpserver

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"
)

// Serve owns accepted connections and handlers until they finish. Closing
// sockets after a drain deadline cancels requests, but cannot kill a handler.
// The host must terminate the process if a handler refuses to finish; returning
// here would release stores underneath it. Hijacked sessions keep their separate
// explicit owner, while this function still joins their HTTP upgrade handler.
// Serve takes exclusive ownership of server configuration for its lifetime;
// callers must capture any immutable handler test seam before starting it.
func Serve(
	ctx context.Context,
	server *http.Server,
	listener net.Listener,
	shutdownTimeout time.Duration,
) error {
	base := context.Background()
	if server.BaseContext != nil {
		base = server.BaseContext(listener)
	}

	handlerContext, cancelHandlers := context.WithCancel(base)
	defer cancelHandlers()

	var connections, handlers sync.WaitGroup
	handler, connState := server.Handler, server.ConnState
	if handler == nil {
		handler = http.DefaultServeMux
	}

	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlers.Add(1)
		defer handlers.Done()

		handler.ServeHTTP(w, r)
	})
	server.BaseContext = func(net.Listener) context.Context { return handlerContext }
	server.ConnState = func(conn net.Conn, state http.ConnState) {
		switch state {
		case http.StateNew:
			connections.Add(1)
		case http.StateClosed, http.StateHijacked:
			connections.Done()
		}

		if connState != nil {
			connState(conn, state)
		}
	}
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	var serveErr, shutdownErr error
	select {
	case serveErr = <-served:
		cancelHandlers()

		shutdownErr = server.Close()
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		shutdownErr = server.Shutdown(shutdownCtx)
		cancel()
		if shutdownErr != nil {
			cancelHandlers()
			_ = server.Close()
		}

		serveErr = <-served
	}

	// Serve has stopped accepting before Wait: no new connection can Add, and
	// existing connections keep handler registration alive until closed/hijacked.
	connections.Wait()
	handlers.Wait()
	if errors.Is(serveErr, http.ErrServerClosed) {
		serveErr = nil
	}

	return errors.Join(shutdownErr, serveErr)
}
