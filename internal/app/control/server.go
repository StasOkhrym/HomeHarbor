package control

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/platform/config"
	"github.com/StasOkhrym/homeharbor/internal/platform/httpserver"
)

// serveHTTP supplies the control role default to the shared handler owner.
func serveHTTP(
	ctx context.Context,
	server *http.Server,
	listener net.Listener,
	timeout ...time.Duration,
) error {
	drain := config.DefaultRuntime(false).ShutdownTimeout
	if len(timeout) != 0 {
		drain = timeout[0]
	}

	return httpserver.Serve(ctx, server, listener, drain)
}
