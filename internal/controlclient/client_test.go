package controlclient_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/controlclient"
	"github.com/StasOkhrym/homeharbor/internal/protocol"
)

func newClient(t *testing.T, server *httptest.Server) *controlclient.Client {
	t.Helper()

	base, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	transport := server.Client()
	transport.Timeout = time.Second

	client, err := controlclient.New(base, transport)
	if err != nil {
		t.Fatal(err)
	}

	return client
}

func TestCancellationBoundsRequest(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	defer server.Close()

	client := newClient(t, server)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := client.Challenge(ctx, "invite"); done <- err }()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v, want context canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("request did not stop after cancellation")
	}
}

func TestOversizedResponseRejected(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(
			w,
			`{"version":1,"network_id":"n"}`+strings.Repeat(" ", controlclient.MaxJSONBytes),
		)
	}))
	defer server.Close()

	client := newClient(t, server)

	_, err := client.Challenge(context.Background(), "invite")

	if err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("oversized response: %v", err)
	}
}

func TestUnexpectedRedirectRejected(t *testing.T) {
	var followed atomic.Int32
	destination := httptest.NewServer(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { followed.Add(1) }),
	)
	defer destination.Close()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()

	client := newClient(t, server)

	_, err := client.Enroll(context.Background(), protocol.EnrollmentRequest{Token: "secret-token"})
	var status *controlclient.StatusError

	if !errors.As(err, &status) || status.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("redirect result: %v", err)
	}
	if followed.Load() != 0 {
		t.Fatal("redirect leaked enrollment token")
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatal("status error leaked secrets")
	}
}

func TestStatusMapsToTypedError(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, `{"credential":"server-secret"}`)
	}))
	defer server.Close()

	client := newClient(t, server)

	_, err := client.Challenge(context.Background(), "secret-invite")
	var status *controlclient.StatusError

	if !errors.As(err, &status) || status.StatusCode != http.StatusConflict {
		t.Fatalf("status result: %v", err)
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatal("error reflected untrusted data")
	}
}

func TestClaimNotAutomaticallyRetried(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client := newClient(t, server)

	_, err := client.Claim(context.Background(), "invite", protocol.ClaimProof{})
	var status *controlclient.StatusError

	if !errors.As(err, &status) || status.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("claim result: %v", err)
	}
	if attempts.Load() != 1 {
		t.Fatalf("signed claim sent %d times", attempts.Load())
	}
}

func TestConstructorRequiresBoundedVerifiedTransport(t *testing.T) {
	base, _ := url.Parse("https://control.example")
	if _, err := controlclient.New(base, &http.Client{}); err == nil {
		t.Fatal("unbounded HTTP client accepted")
	}

	bad, _ := url.Parse("http://control.example")
	if _, err := controlclient.New(bad, nil); err == nil {
		t.Fatal("remote plaintext accepted")
	}

	server := httptest.NewTLSServer(
		http.HandlerFunc(
			func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusCreated) },
		),
	)
	defer server.Close()

	untrusted, _ := url.Parse(server.URL)
	client, err := controlclient.New(untrusted, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Enroll(context.Background(), protocol.EnrollmentRequest{})

	if err == nil {
		t.Fatal("untrusted TLS certificate accepted")
	}
}
