package protocol

import (
	"time"

	"github.com/StasOkhrym/homeharbor/internal/invite"
)

type InviteRecord struct {
	InviteID           string              `json:"invite_id"`
	ProfileID          string              `json:"profile_id"`
	DeviceID           string              `json:"device_id"`
	DevicePublic       []byte              `json:"device_public_key"`
	WireGuardPublicKey []byte              `json:"wireguard_public_key"`
	Permit             invite.SignedPermit `json:"permit"`
	Proof              invite.Proof        `json:"proof"`
	Status             string              `json:"status"`
	CreatedAt          time.Time           `json:"created_at"`
	ApprovedAt         *time.Time          `json:"approved_at,omitempty"`
	FailedCodeAttempts int                 `json:"failed_code_attempts"`
	BlockedAt          *time.Time          `json:"blocked_at,omitempty"`
}

type InviteApprovalResult struct {
	InviteID  string `json:"invite_id"`
	DeviceID  string `json:"device_id"`
	ProfileID string `json:"profile_id"`
	Status    string `json:"status"`
}
