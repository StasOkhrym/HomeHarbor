package storage

import (
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
)

func TestPostgresPersonalPasskeyWritesFenceAccountAndCounter(t *testing.T) {
	store, replica, pool, scope, _, now := totpSQLFixture(t, false)
	credential := webauthn.Credential{
		ID:              []byte("personal-key"),
		PublicKey:       []byte("public"),
		AttestationType: "none",
		Authenticator:   webauthn.Authenticator{SignCount: 1},
	}

	if err := store.SavePersonalCredential(
		t.Context(),
		scope,
		identity.NamedCredential{Name: "MacBook", Credential: credential, CreatedAt: now},
	); err != nil {
		t.Fatal(err)
	}

	credential.Authenticator.SignCount = 2

	if err := replica.UpdatePersonalCredential(
		t.Context(),
		scope,
		credential,
		now.Add(time.Second),
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("stale password proof updated credential", err)
	}

	scope.AuthVersion = 4

	if err := replica.UpdatePersonalCredential(
		t.Context(),
		scope,
		credential,
		now.Add(time.Second),
	); err != nil {
		t.Fatal(err)
	}

	if err := store.UpdatePersonalCredential(
		t.Context(),
		scope,
		credential,
		now.Add(2*time.Second),
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("credential counter replay accepted", err)
	}

	state, err := store.FactorState(t.Context(), scope)

	if err != nil || len(state.Passkeys) != 1 || state.Passkeys[0].Name != "MacBook" ||
		state.Passkeys[0].ID != base64.RawURLEncoding.EncodeToString(credential.ID) ||
		state.Passkeys[0].LastUsedAt == nil ||
		!state.Passkeys[0].LastUsedAt.Equal(now.Add(time.Second)) {
		t.Fatalf("incorrect personal metadata: %+v %v", state, err)
	}

	if _, err := pool.Exec(
		t.Context(),
		`INSERT INTO admin_accounts(account_id,email,role,status,password_hash,user_handle)VALUES('b','b@example.test','admin','active','hash','handle-b')`,
	); err != nil {
		t.Fatal(err)
	}

	foreign := identity.AccountScope{AccountID: "b", AuthVersion: 1, Purpose: identity.SessionAdmin}
	for _, err := range []error{replica.UpdatePersonalCredential(t.Context(), foreign, credential, now), store.RemovePasskey(t.Context(), foreign, credential.ID), store.SavePersonalCredential(t.Context(), foreign, identity.NamedCredential{Name: "Stolen ID", Credential: credential, CreatedAt: now})} {
		if !errors.Is(err, identity.ErrInvalidCredential) {
			t.Fatal("foreign account changed owned credential", err)
		}
	}

	foreignState, err := replica.FactorState(t.Context(), foreign)

	if err != nil || len(foreignState.Passkeys) != 0 {
		t.Fatal("foreign account read owned metadata", err)
	}
}

func TestPostgresPersonalPasskeyAndTOTPRemovalSerialize(t *testing.T) {
	store, replica, _, scope, record, now := totpSQLFixture(t, true)

	if err := store.SavePendingTOTP(t.Context(), scope, record); err != nil {
		t.Fatal(err)
	}

	if err := store.ConfirmTOTP(t.Context(), scope, record.ID, 66666666, now); err != nil {
		t.Fatal(err)
	}

	scope.AuthVersion = 4
	var removed atomic.Int32
	var group sync.WaitGroup
	for _, remove := range []func() error{
		func() error { return store.RemovePasskey(t.Context(), scope, []byte("owner-key")) },
		func() error { return replica.RemoveTOTP(t.Context(), scope) },
	} {
		group.Go(func() {
			err := remove()
			if err == nil {
				removed.Add(1)
			} else if !errors.Is(err, identity.ErrInvalidCredential) && !errors.Is(err, identity.ErrLastMFA) {
				t.Error(err)
			}
		})
	}

	group.Wait()

	if removed.Load() != 1 {
		t.Fatalf("concurrent method removals=%d", removed.Load())
	}

	scope.AuthVersion = 5

	state, err := store.FactorState(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}

	count := len(state.Passkeys)
	if state.TOTP {
		count++
	}

	if count != 1 {
		t.Fatalf("last-factor invariant lost: %+v", state)
	}

	if state.TOTP {
		err = replica.RemoveTOTP(t.Context(), scope)
	} else {
		err = replica.RemovePasskey(t.Context(), scope, []byte("owner-key"))
	}

	if !errors.Is(err, identity.ErrLastMFA) {
		t.Fatal("fresh principal removed last remaining factor", err)
	}
}

func TestPostgresPersonalPasskeyLimitDoesNotAffectOtherAccounts(t *testing.T) {
	store, _, pool, scope, _, now := totpSQLFixture(t, false)
	for index := range 12 {
		credential := webauthn.Credential{
			ID:              []byte{byte(index)},
			PublicKey:       []byte("public"),
			AttestationType: "none",
		}

		if err := store.SavePersonalCredential(
			t.Context(),
			scope,
			identity.NamedCredential{
				Name:       fmt.Sprintf("Key %d", index),
				Credential: credential,
				CreatedAt:  now,
			},
		); err != nil {
			t.Fatal(err)
		}

		scope.AuthVersion++
	}

	extra := identity.NamedCredential{
		Name: "extra",
		Credential: webauthn.Credential{
			ID:              []byte("extra"),
			PublicKey:       []byte("public"),
			AttestationType: "none",
		},
		CreatedAt: now,
	}

	if err := store.SavePersonalCredential(
		t.Context(),
		scope,
		extra,
	); !errors.Is(
		err,
		identity.ErrFactorLimit,
	) {
		t.Fatalf("unbounded credential set admitted: %v", err)
	}

	if _, err := pool.Exec(
		t.Context(),
		`INSERT INTO admin_accounts(account_id,email,role,status,password_hash,user_handle)VALUES('b','b@example.test','admin','active','hash','handle-b')`,
	); err != nil {
		t.Fatal(err)
	}

	if err := store.SavePersonalCredential(
		t.Context(),
		identity.AccountScope{AccountID: "b", AuthVersion: 1, Purpose: identity.SessionAdmin},
		extra,
	); err != nil {
		t.Fatal("one account exhausted another's method allowance", err)
	}
}
