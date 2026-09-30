package storage_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/sokhrym/go-tunnels/internal/app/control/workflows"
	"github.com/sokhrym/go-tunnels/internal/control/httpapi"
)

func TestPostgresHTTPClaimReplayReturnsInvalidClaim400(t *testing.T) {
	if os.Getenv("TEST_REDIS_URL") == "" {
		t.Skip("TEST_REDIS_URL is not set")
	}
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.activation.ApproveSigned(ctx, f.approval); err != nil {
		t.Fatal(err)
	}
	f.publish(t)
	c, err := f.activation.Challenge(ctx, f.record.InviteID)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := workflows.SignClaim(c, f.deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	h := httpapi.NewActivationHandler(f.activation, f.activation)
	for _, want := range []int{http.StatusOK, http.StatusBadRequest} {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/invites/"+f.record.InviteID+"/claim", bytes.NewReader(body))
		r.SetPathValue("id", f.record.InviteID)
		w := httptest.NewRecorder()
		h.Claim(w, r)
		if w.Code != want {
			t.Fatalf("status=%d want=%d body=%s", w.Code, want, w.Body)
		}
		if want == http.StatusBadRequest && w.Body.String() != "{\"code\":\"invalid_activation_claim\",\"error\":\"invalid activation claim\"}\n" {
			t.Fatalf("replay response=%s", w.Body)
		}
	}
}
