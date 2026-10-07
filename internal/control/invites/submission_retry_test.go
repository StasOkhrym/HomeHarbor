package invites_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	domainpkg "github.com/StasOkhrym/homeharbor/internal/control/invites"
	"github.com/StasOkhrym/homeharbor/internal/invite"
	memorystore "github.com/StasOkhrym/homeharbor/internal/testutil/control/invites"
)

func TestProofSubmissionRetryPreservesExactPublicIdentity(t *testing.T) {
	root, key, _ := ed25519.GenerateKey(rand.Reader)

	_, device, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	local, _ := invite.New("home", "family", time.Hour, now, rand.Reader)

	permit, _ := invite.SignPermit(local.Permit, key, "root-1")

	proof, _ := local.Proof("linux", device, local.Code, bytes.Repeat([]byte{7}, 32))
	s := domainpkg.NewService(
		memorystore.NewRepository(),
		root,
		"home",
		func() time.Time { return now },
	)
	for range 2 {
		if err := s.SubmitProof(context.Background(), permit, proof); err != nil {
			t.Fatal("same proof retry failed:", err)
		}
	}

	wrong, _ := local.Proof("other", device, local.Code, bytes.Repeat([]byte{7}, 32))

	if err := s.SubmitProof(context.Background(), permit, wrong); err == nil {
		t.Fatal("different proof replaced invite")
	}
}
