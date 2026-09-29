package devices

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestEnrollmentTokenIsSingleUse(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	service := NewService(store, func() time.Time { return now }, fixedRandom{'x'})

	issued, err := service.IssueEnrollmentToken(context.Background(), RoleClient, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	device, err := service.Enroll(context.Background(), EnrollRequest{
		Token: issued.Token, Name: "laptop", IdentityPublicKey: "identity-pub", WireGuardPublicKey: "wg-pub",
	})
	if err != nil {
		t.Fatalf("Enroll() error = %v", err)
	}
	if device.Role != RoleClient || device.Status != StatusActive {
		t.Fatalf("device = %#v", device)
	}
	if device.Credential == "" {
		t.Fatal("enrollment credential is empty")
	}
	if _, err := service.Enroll(context.Background(), EnrollRequest{Token: issued.Token, Name: "second", IdentityPublicKey: "i2", WireGuardPublicKey: "w2"}); !errors.Is(err, ErrInvalidEnrollmentToken) {
		t.Fatalf("second Enroll() error = %v", err)
	}
}

func TestEnrollmentTokenExpires(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	service := NewService(store, func() time.Time { return now }, fixedRandom{'y'})
	issued, err := service.IssueEnrollmentToken(context.Background(), RoleGateway, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	_, err = service.Enroll(context.Background(), EnrollRequest{Token: issued.Token, Name: "gateway", IdentityPublicKey: "identity", WireGuardPublicKey: "wireguard"})
	if !errors.Is(err, ErrInvalidEnrollmentToken) {
		t.Fatalf("Enroll() error = %v", err)
	}
}

func TestRevokeDeviceIsIdempotent(t *testing.T) {
	store := NewMemoryStore()
	service := NewService(store, time.Now, fixedRandom{'z'})
	issued, _ := service.IssueEnrollmentToken(context.Background(), RoleClient, time.Hour)
	device, _ := service.Enroll(context.Background(), EnrollRequest{Token: issued.Token, Name: "phone", IdentityPublicKey: "identity", WireGuardPublicKey: "wireguard"})
	if err := service.Revoke(context.Background(), device.ID); err != nil {
		t.Fatal(err)
	}
	if err := service.Revoke(context.Background(), device.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := store.Device(context.Background(), device.ID)
	if got.Status != StatusRevoked {
		t.Fatalf("status = %q", got.Status)
	}
}

func TestEnrollPublishesDomainEvent(t *testing.T) {
	store := NewMemoryStore()
	publisher := &recordPublisher{}
	service := NewService(store, time.Now, fixedRandom{'e'}, WithPublisher(publisher))
	issued, _ := service.IssueEnrollmentToken(context.Background(), RoleClient, time.Hour)
	device, err := service.Enroll(context.Background(), EnrollRequest{Token: issued.Token, Name: "laptop", IdentityPublicKey: "i", WireGuardPublicKey: "w"})
	if err != nil {
		t.Fatal(err)
	}
	if len(publisher.events) != 1 || publisher.events[0].Type != "device.enrolled" || publisher.events[0].AggregateID != device.ID {
		t.Fatalf("events=%#v", publisher.events)
	}
}

func TestEnrollUsesAtomicStoreOperation(t *testing.T) {
	store := &atomicEnrollmentStore{MemoryStore: NewMemoryStore()}
	service := NewService(store, time.Now, fixedRandom{'a'})
	issued, err := service.IssueEnrollmentToken(context.Background(), RoleClient, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Enroll(context.Background(), EnrollRequest{Token: issued.Token, Name: "phone", IdentityPublicKey: "i", WireGuardPublicKey: "w"})
	if !errors.Is(err, errAtomicEnrollment) {
		t.Fatalf("Enroll() error = %v, want atomic store error", err)
	}
}

func TestRotateCredentialRevokesPreviousCredential(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	service := NewService(store, func() time.Time { return now }, &sequenceRandom{})
	issued, err := service.IssueEnrollmentToken(context.Background(), RoleClient, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	device, err := service.Enroll(context.Background(), EnrollRequest{
		Token: issued.Token, Name: "phone", IdentityPublicKey: "i", WireGuardPublicKey: "w",
	})
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := service.RotateCredential(context.Background(), device.ID, device.Credential)
	if err != nil {
		t.Fatal(err)
	}
	if rotated == device.Credential {
		t.Fatal("rotation returned the previous credential")
	}
	if _, err := service.Authenticate(context.Background(), device.Credential); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("old credential authentication error = %v", err)
	}
	if got, err := service.Authenticate(context.Background(), rotated); err != nil || got.ID != device.ID {
		t.Fatalf("new credential authentication = %#v, %v", got, err)
	}
}

var errAtomicEnrollment = errors.New("atomic enrollment failed")

type atomicEnrollmentStore struct{ *MemoryStore }

func (s *atomicEnrollmentStore) Enroll(context.Context, [32]byte, time.Time, Device) (Role, error) {
	return "", errAtomicEnrollment
}

type recordPublisher struct{ events []Event }

func (r *recordPublisher) Publish(_ context.Context, event Event) error {
	r.events = append(r.events, event)
	return nil
}

type fixedRandom struct{ b byte }

func (f fixedRandom) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = f.b
	}

	return len(p), nil
}

type sequenceRandom struct{ next byte }

func (r *sequenceRandom) Read(p []byte) (int, error) {
	r.next++
	for i := range p {
		p[i] = r.next
	}

	return len(p), nil
}
