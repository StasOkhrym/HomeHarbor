package node

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/protocol"
)

func TestEnrollRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).
			Encode(protocol.EnrolledDevice{ID: "device", Credential: "secret", CredentialExpiresAt: time.Now().Add(time.Hour)})

		_, _ = w.Write([]byte(strings.Repeat(" ", 1<<20)))
	}))
	defer server.Close()

	state, err := NewState()
	if err != nil {
		t.Fatal(err)
	}

	if err := Enroll(
		context.Background(),
		server.Client(),
		server.URL,
		"token",
		"name",
		&state,
	); err == nil {
		t.Fatal("oversized and trailing response accepted")
	}
}

func TestEnrollRejectsRedirectWithoutSendingToken(t *testing.T) {
	arrivals := 0
	destination := httptest.NewServer(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { arrivals++ }),
	)
	defer destination.Close()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()

	state, err := NewState()
	if err != nil {
		t.Fatal(err)
	}

	if err := Enroll(
		context.Background(),
		server.Client(),
		server.URL,
		"token-secret",
		"name",
		&state,
	); err == nil {
		t.Fatal("redirect accepted")
	}

	if arrivals != 0 {
		t.Fatal("token followed redirect")
	}
}
