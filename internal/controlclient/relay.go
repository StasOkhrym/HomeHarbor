package controlclient

import (
	"context"
	"net/http"

	"github.com/StasOkhrym/homeharbor/internal/protocol"
)

func (c *Client) IssueRelaySession(
	ctx context.Context,
	credential string,
	request protocol.RelaySessionRequest,
) (protocol.RelaySession, error) {
	var result protocol.RelaySession

	err := c.request(
		ctx,
		http.MethodPost,
		"/api/v1/relay-sessions",
		credential,
		nil,
		request,
		&result,
		http.StatusCreated,
		false,
	)

	return result, err
}
