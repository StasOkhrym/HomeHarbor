package invites

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sokhrym/go-tunnels/internal/invite"
)

// Approval responses must be safe to deliver to the companion.
func TestApprovalResultHasNoCredentialSurface(t *testing.T) {
	encoded, err := json.Marshal(ApprovalResult{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "\"device\":") || strings.Contains(string(encoded), "credential") {
		t.Fatalf("approval exposes device bootstrap: %s", encoded)
	}
}

func TestSignedApprovalRequiresApplicationWorkflow(t *testing.T) {
	s := NewService(NewMemoryStore(), nil, "home", nil)
	_, err := s.ApproveSigned(context.Background(), invite.SignedApproval{})
	if err == nil || !strings.Contains(err.Error(), "workflow") {
		t.Fatalf("missing workflow should fail explicitly, got %v", err)
	}
}
