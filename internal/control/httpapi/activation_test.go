package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/StasOkhrym/homeharbor/internal/control/workflows"
	"github.com/StasOkhrym/homeharbor/internal/protocol"
)

type activationUnavailable struct{}

func (activationUnavailable) Challenge(context.Context, string) (protocol.ClaimChallenge, error) {
	return protocol.ClaimChallenge{}, workflows.ErrNotReady
}

func (activationUnavailable) Claim(
	context.Context,
	string,
	protocol.ClaimProof,
) (workflows.ClaimResult, error) {
	return workflows.ClaimResult{}, protocol.ErrInvalidClaim
}

func TestActivationHTTPRejectsUnknownAndTrailingClaimFields(t *testing.T) {
	h := NewActivationHandler(activationUnavailable{}, activationUnavailable{})
	for _, body := range []string{`{"private_key":"never-send-this"}`, `{} {}`, `{"challenge":{},"signature":"bad","credential":"injected"}`} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(
			http.MethodPost,
			"/api/v1/invites/i/claim",
			strings.NewReader(body),
		)

		r.SetPathValue("id", "i")
		h.Claim(w, r)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%s", w.Code, w.Body)
		}
		if strings.Contains(w.Body.String(), "never-send-this") {
			t.Fatal("sensitive input echoed")
		}
	}
}

func TestActivationHTTPNotReadyAndNoStoreCacheHeaders(t *testing.T) {
	h := NewActivationHandler(activationUnavailable{}, activationUnavailable{})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/invites/i/challenge", nil)

	r.SetPathValue("id", "i")
	h.Challenge(w, r)

	if w.Code != http.StatusConflict {
		t.Fatalf("status=%d", w.Code)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("activation response can be cached")
	}

	var response map[string]any

	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}

	if _, ok := response["credential"]; ok {
		t.Fatal("challenge leaked credential")
	}
}
