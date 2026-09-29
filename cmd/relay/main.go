package main

import (
	"flag"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sokhrym/go-tunnels/internal/platform/config"
	"github.com/sokhrym/go-tunnels/internal/relay"
	"log/slog"
	"net/http"
	"os"
	"time"
)

func main() {
	path := flag.String("config", "config/relay.toml", "relay configuration path")
	flag.Parse()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := config.LoadRelayServer(*path)
	if err != nil {
		logger.Error("load config", "error", err)
		os.Exit(1)
	}
	mux := http.NewServeMux()
	mux.Handle("/relay/v1", relay.WebSocketHandler{Hub: relay.NewHub(), Tickets: relay.TicketIssuer{Key: []byte(cfg.Security.TicketKey)}})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.Handle("GET /metrics", promhttp.Handler())
	server := http.Server{Addr: cfg.Server.ListenAddress, Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
	logger.Info("relay listening", "address", cfg.Server.ListenAddress)
	if err = server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("serve relay", "error", err)
		os.Exit(1)
	}
}
