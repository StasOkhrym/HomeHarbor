package controlclient

import (
	"context"
	"net/http"
	"net/url"

	"github.com/StasOkhrym/homeharbor/internal/invite"
	"github.com/StasOkhrym/homeharbor/internal/protocol"
)

func (c *Client) SubmitInviteProof(
	ctx context.Context,
	permit invite.SignedPermit,
	proof invite.Proof,
) error {
	return c.request(
		ctx,
		http.MethodPost,
		"/api/v1/invites/proof",
		"",
		nil,
		protocol.InviteProofSubmission{
			Permit: permit,
			Proof:  proof,
		},
		nil,
		http.StatusAccepted,
		true,
	)
}

func (c *Client) Challenge(ctx context.Context, inviteID string) (protocol.ClaimChallenge, error) {
	var result protocol.ClaimChallenge

	err := c.request(
		ctx,
		http.MethodPost,
		"/api/v1/invites/"+url.PathEscape(inviteID)+"/challenge",
		"",
		nil,
		nil,
		&result,
		http.StatusOK,
		true,
	)

	return result, err
}

// Claim retains the complete device response so callers can pin identity,
// role, status, and public keys before publishing a credential lease.
func (c *Client) Claim(
	ctx context.Context,
	inviteID string,
	proof protocol.ClaimProof,
) (protocol.EnrolledDevice, error) {
	var result struct {
		Device protocol.EnrolledDevice `json:"device"`
	}

	err := c.request(
		ctx,
		http.MethodPost,
		"/api/v1/invites/"+url.PathEscape(inviteID)+"/claim",
		"",
		nil,
		proof,
		&result,
		http.StatusOK,
		true,
	)

	return result.Device, err
}
