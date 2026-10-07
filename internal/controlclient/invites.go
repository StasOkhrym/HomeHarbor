package controlclient

import (
	"context"
	"net/http"
	"net/url"

	"github.com/StasOkhrym/homeharbor/internal/invite"
	"github.com/StasOkhrym/homeharbor/internal/protocol"
	"github.com/StasOkhrym/homeharbor/internal/snapshot"
)

func (c *Client) Invite(ctx context.Context, id string) (protocol.InviteRecord, error) {
	var result protocol.InviteRecord

	err := c.request(
		ctx,
		http.MethodGet,
		"/api/v1/invites/"+url.PathEscape(id),
		"",
		nil,
		nil,
		&result,
		http.StatusOK,
		false,
	)

	return result, err
}

func (c *Client) ApproveInvite(
	ctx context.Context,
	id string,
	approval invite.SignedApproval,
) (protocol.InviteApprovalResult, error) {
	var result protocol.InviteApprovalResult

	err := c.request(
		ctx,
		http.MethodPost,
		"/api/v1/invites/"+url.PathEscape(id)+"/approval",
		"",
		nil,
		protocol.InviteApprovalRequest{Approval: approval},
		&result,
		http.StatusOK,
		true,
	)

	return result, err
}

func (c *Client) CompanionChallenge(ctx context.Context) (string, error) {
	var result struct {
		Nonce string `json:"nonce"`
	}

	err := c.request(
		ctx,
		http.MethodGet,
		"/api/v1/coordination/snapshot/companion-challenge",
		"",
		nil,
		nil,
		&result,
		http.StatusOK,
		false,
	)

	return result.Nonce, err
}

func (c *Client) CompanionSnapshot(
	ctx context.Context,
	headers http.Header,
) (snapshot.Envelope, error) {
	var result snapshot.Envelope

	err := c.request(
		ctx,
		http.MethodGet,
		"/api/v1/coordination/snapshot/companion",
		"",
		headers,
		nil,
		&result,
		http.StatusOK,
		false,
	)

	return result, err
}

func (c *Client) PublishSnapshot(ctx context.Context, envelope snapshot.Envelope) error {
	return c.request(
		ctx,
		http.MethodPost,
		"/api/v1/coordination/snapshots",
		"",
		nil,
		envelope,
		nil,
		http.StatusNoContent,
		false,
	)
}
