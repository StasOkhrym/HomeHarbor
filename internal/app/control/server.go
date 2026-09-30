package control

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"
)

// serveHTTP joins shutdown before its lifecycle component returns. Serve alone
// returns as soon as the listener closes, while active handlers may still own DB
// connections; closing the app's stores at that point races those handlers.
func serveHTTP(ctx context.Context, server *http.Server, listener net.Listener) error {
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	select {
	case err := <-served:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := server.Shutdown(shutdownCtx)
	if err != nil {
		// Graceful shutdown timed out: terminate remaining connections before
		// releasing dependent stores instead of leaking the listener forever.
		_ = server.Close()
	}
	serveErr := <-served
	if errors.Is(serveErr, http.ErrServerClosed) {
		serveErr = nil
	}
	return errors.Join(err, serveErr)
}
