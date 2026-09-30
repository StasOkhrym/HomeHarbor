package devices

import (
	"context"
	"errors"
	"testing"
	"time"
)

type failingPublisher struct{}

func (failingPublisher) Publish(context.Context, Event) error {
	return errors.New("publication unavailable")
}

func TestExplicitPublicationFailureIsNotIgnored(t *testing.T) {
	s := NewService(NewMemoryStore(), time.Now, nil, WithPublisher(failingPublisher{}))
	token, err := s.IssueEnrollmentToken(context.Background(), RoleClient, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	id, wg := validPublicKeys(t)
	if _, err := s.Enroll(context.Background(), EnrollRequest{Token: token.Token, Name: "linux", IdentityPublicKey: id, WireGuardPublicKey: wg}); err == nil {
		t.Fatal("publication failure ignored")
	}
}
