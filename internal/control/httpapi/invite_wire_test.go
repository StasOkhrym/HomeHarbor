package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/invites"
	"github.com/StasOkhrym/homeharbor/internal/invite"
)

// Literal field order/tags come from c184f97 control/invites.Record and
// ApprovalResult, which the pre-extraction handlers encoded directly.
const inviteRecordJSON = `{"invite_id":"invite-1","profile_id":"profile-1","device_id":"device-1","device_public_key":"AQID","wireguard_public_key":"BAUG","permit":{"version":1,"key_id":"root-1","payload":"BwgJ","signature":"CgsM"},"proof":{"version":1,"invite_id":"invite-1","device_id":"device-1","device_public_key":"DQ4P","wireguard_public_key":"EBES","code_digest":"ExQV","signature":"FhcY","device_signature":"GRob"},"status":"approved","created_at":"2026-10-02T10:00:00Z"`

func TestInviteHTTPPreservesPreExtractionJSON(t *testing.T) {
	now := time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC)
	approved := now.Add(time.Minute)
	blocked := now.Add(2 * time.Minute)
	record := invites.Record{
		InviteID:           "invite-1",
		ProfileID:          "profile-1",
		DeviceID:           "device-1",
		DevicePublic:       []byte{1, 2, 3},
		WireGuardPublicKey: []byte{4, 5, 6},
		Permit: invite.SignedPermit{
			Version:   1,
			KeyID:     "root-1",
			Payload:   []byte{7, 8, 9},
			Signature: []byte{10, 11, 12},
		},
		Proof: invite.Proof{
			Version:            1,
			InviteID:           "invite-1",
			DeviceID:           "device-1",
			DevicePublicKey:    []byte{13, 14, 15},
			WireGuardPublicKey: []byte{16, 17, 18},
			CodeDigest:         []byte{19, 20, 21},
			Signature:          []byte{22, 23, 24},
			DeviceSignature:    []byte{25, 26, 27},
		},
		Status:             invites.StatusApproved,
		CreatedAt:          now,
		FailedCodeAttempts: 3,
	}
	for _, test := range []struct {
		name              string
		approved, blocked *time.Time
		suffix            string
	}{
		{"omitted timestamps", nil, nil, `,"failed_code_attempts":3}`},
		{"present timestamps", &approved, &blocked, `,"approved_at":"2026-10-02T10:01:00Z","failed_code_attempts":3,"blocked_at":"2026-10-02T10:02:00Z"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			record.ApprovedAt = test.approved
			record.BlockedAt = test.blocked
			want := inviteRecordJSON + test.suffix

			// Check the original domain projection as well as the current HTTP adapter.
			original, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}

			if string(original) != want {
				t.Fatalf("baseline domain JSON = %s, want %s", original, want)
			}

			server := Server{invites: inviteWireService{record: record}}
			request := httptest.NewRequest(http.MethodGet, "/api/v1/invites/invite-1", nil)

			request.SetPathValue("id", "invite-1")
			response := httptest.NewRecorder()

			server.getInvite(response, request)

			if response.Code != http.StatusOK || response.Body.String() != want+"\n" {
				t.Fatalf("HTTP %d: %s, want %s", response.Code, response.Body.String(), want)
			}
		})
	}

	server := Server{invites: inviteWireService{record: record}}
	response := httptest.NewRecorder()

	server.approveInvite(
		response,
		httptest.NewRequest(
			http.MethodPost,
			"/api/v1/invites/invite-1/approval",
			strings.NewReader(`{"approval":{}}`),
		),
	)
	const wantApproval = `{"invite_id":"invite-1","device_id":"device-1","profile_id":"profile-1","status":"approved"}`

	original, err := json.Marshal(
		invites.ApprovalResult{
			Record:    record,
			InviteID:  record.InviteID,
			DeviceID:  record.DeviceID,
			ProfileID: record.ProfileID,
			Status:    record.Status,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if string(original) != wantApproval {
		t.Fatalf("baseline approval JSON = %s", original)
	}
	if response.Code != http.StatusOK || response.Body.String() != wantApproval+"\n" {
		t.Fatalf("approval HTTP %d: %s", response.Code, response.Body.String())
	}
}

type inviteWireService struct{ record invites.Record }

func (s inviteWireService) SubmitProof(context.Context, invite.SignedPermit, invite.Proof) error {
	return nil
}

func (s inviteWireService) Get(
	context.Context,
	string,
) (invites.Record, error) {
	return s.record, nil
}

func (s inviteWireService) ApproveSigned(
	context.Context,
	invite.SignedApproval,
) (invites.ApprovalResult, error) {
	return invites.ApprovalResult{
		Record:    s.record,
		InviteID:  s.record.InviteID,
		DeviceID:  s.record.DeviceID,
		ProfileID: s.record.ProfileID,
		Status:    s.record.Status,
	}, nil
}
