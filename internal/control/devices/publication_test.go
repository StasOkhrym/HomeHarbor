package devices_test

import (
	"context"
	"errors"
	"testing"
	"time"

	domainpkg "github.com/StasOkhrym/homeharbor/internal/control/devices"
	memorystore "github.com/StasOkhrym/homeharbor/internal/testutil/control/devices"
)

type failingPublisher struct{}

func (failingPublisher) Publish(context.Context, domainpkg.Event) error {
	return errors.New("publication unavailable")
}

func TestExplicitPublicationFailureIsNotIgnored(t *testing.T) {
	s := domainpkg.NewService(
		memorystore.NewRepository(),
		time.Now,
		nil,
		domainpkg.WithPublisher(failingPublisher{}),
	)

	token, err := s.IssueEnrollmentToken(context.Background(), domainpkg.RoleClient, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	id, wg := validPublicKeys(t)

	if _, err := s.Enroll(
		context.Background(),
		domainpkg.EnrollRequest{
			Token:              token.Token,
			Name:               "linux",
			IdentityPublicKey:  id,
			WireGuardPublicKey: wg,
		},
	); err == nil {
		t.Fatal("publication failure ignored")
	}
}
