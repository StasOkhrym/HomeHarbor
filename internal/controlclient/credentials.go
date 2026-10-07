package controlclient

import (
	"context"
	"net/http"

	"github.com/StasOkhrym/homeharbor/internal/protocol"
)

func (c *Client) Enroll(
	ctx context.Context,
	request protocol.EnrollmentRequest,
) (protocol.EnrolledDevice, error) {
	var result protocol.EnrolledDevice

	err := c.request(
		ctx,
		http.MethodPost,
		"/api/v1/enroll",
		"",
		nil,
		request,
		&result,
		http.StatusCreated,
		false,
	)

	return result, err
}

func (c *Client) RotateCredential(
	ctx context.Context,
	credential string,
) (protocol.CredentialLease, error) {
	var result protocol.CredentialLease

	err := c.request(
		ctx,
		http.MethodPost,
		"/api/v1/devices/credentials/rotate",
		credential,
		nil,
		nil,
		&result,
		http.StatusOK,
		false,
	)

	return result, err
}

func (c *Client) CredentialChallenge(
	ctx context.Context,
	deviceID string,
) (protocol.CredentialChallenge, error) {
	var result protocol.CredentialChallenge

	err := c.request(
		ctx,
		http.MethodPost,
		"/api/v1/devices/credentials/challenge",
		"",
		nil,
		struct {
			DeviceID string `json:"device_id"`
		}{deviceID},
		&result,
		http.StatusOK,
		true,
	)

	return result, err
}

func (c *Client) RecoverCredential(
	ctx context.Context,
	proof protocol.CredentialProof,
) (protocol.CredentialLease, error) {
	var result protocol.CredentialLease

	err := c.request(
		ctx,
		http.MethodPost,
		"/api/v1/devices/credentials/recovery",
		"",
		nil,
		proof,
		&result,
		http.StatusOK,
		true,
	)

	return result, err
}
