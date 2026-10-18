package transactions_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
	"github.com/StasOkhrym/homeharbor/internal/control/workflows"
)

func TestPostgresAdministratorDirectoryRequiresLiveOwnerAndReturnsOnlySummaries(t *testing.T) {
	flow, store, pool, _, owner, _ := accountMailFixture(t)

	invited, err := flow.InviteAdmin(t.Context(), owner, "helper@example.test")
	if err != nil {
		t.Fatal(err)
	}

	directory := workflows.NewAccountAdministration(store)

	accounts, err := directory.Administrators(t.Context(), owner)

	if err != nil || len(accounts) != 2 {
		t.Fatal("owner directory unavailable", len(accounts), err)
	}
	if accounts[0].ID != identity.OwnerAccountID || accounts[0].Role != identity.RoleOwner ||
		!accounts[0].EmailVerified ||
		accounts[1].ID != invited.ID ||
		accounts[1].Status != identity.AccountInvited ||
		accounts[1].EmailVerified {
		t.Fatal("incorrect account summaries")
	}

	encoded, err := json.Marshal(accounts)
	if err != nil {
		t.Fatal(err)
	}

	for _, private := range []string{"password_hash", "auth_version", "user_handle", "$argon2id"} {
		if strings.Contains(string(encoded), private) {
			t.Fatal("private account authority in summary", private)
		}
	}

	for _, change := range []func(*identity.Principal){
		func(p *identity.Principal) { p.Role = identity.RoleAdmin },
		func(p *identity.Principal) { p.Purpose = identity.SessionEnrollment },
		func(p *identity.Principal) { p.AuthVersion++ },
		func(p *identity.Principal) { p.AccountID = invited.ID },
	} {
		invalid := owner

		change(&invalid)

		got, err := directory.Administrators(t.Context(), invalid)

		if !errors.Is(err, identity.ErrInvalidCredential) || len(got) != 0 {
			t.Fatal("non-owner or stale proof read directory", err)
		}
	}

	if _, err := flow.RevokeAdmin(t.Context(), owner, invited.ID); err != nil {
		t.Fatal(err)
	}

	accounts, err = directory.Administrators(t.Context(), owner)

	if err != nil || len(accounts) != 2 || accounts[1].Status != identity.AccountRevoked {
		t.Fatal("revoked administrator disappeared from directory", err)
	}

	if _, err := pool.Exec(
		t.Context(),
		`UPDATE admin_accounts SET auth_version=auth_version+1 WHERE account_id=$1`,
		identity.OwnerAccountID,
	); err != nil {
		t.Fatal(err)
	}

	if got, err := directory.Administrators(
		t.Context(),
		owner,
	); !errors.Is(err, identity.ErrInvalidCredential) ||
		len(got) != 0 {
		t.Fatal("old owner proof survived epoch change", err)
	}

	pool.Close()

	if _, err := directory.Administrators(
		t.Context(),
		owner,
	); !errors.Is(
		err,
		identity.ErrSecurityStateUnavailable,
	) {
		t.Fatal("SQL outage was not safe unavailability", err)
	}
}
