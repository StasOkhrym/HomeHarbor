package httpserver

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestServePreservesBaseContextAndConnectionObserver(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	type key struct{}
	entered, closed := make(chan struct{}), make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server := &http.Server{
		BaseContext: func(net.Listener) context.Context { return context.WithValue(context.Background(), key{}, "value") },
		ConnState: func(_ net.Conn, state http.ConnState) {
			if state == http.StateClosed {
				close(closed)
			}
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Context().Value(key{}) != "value" {
				t.Error("caller base context lost")
			}

			close(entered)
			<-r.Context().Done()
		}),
	}
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, server, listener, -time.Nanosecond) }()
	go func() {
		response, err := http.Get("http://" + listener.Addr().String())
		if err == nil {
			_ = response.Body.Close()
		}
	}()
	<-entered
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler was not cancelled/joined")
	}

	<-closed
}
