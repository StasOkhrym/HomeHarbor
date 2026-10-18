package storage

import (
	"bytes"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
	"github.com/StasOkhrym/homeharbor/internal/platform/sealed"
)

func invitedSQLFixture(
	t *testing.T,
) (*Repository, *Repository, *pgxpool.Pool, identity.AccountScope, identity.AccountScope, identity.TOTPRecord, time.Time) {
	t.Helper()
	store, replica, pool, owner, record, now := totpSQLFixture(t, false)
	scope := identity.AccountScope{
		AccountID:   "invited",
		AuthVersion: 2,
		Purpose:     identity.SessionEnrollment,
	}

	if _, err := pool.Exec(
		t.Context(),
		`INSERT INTO admin_accounts(account_id,email,role,status,auth_version,user_handle,password_hash,email_verified_at)VALUES($1,'invited@example.test','admin','invited',2,$2,'password-hash',$3)`,
		scope.AccountID,
		[]byte("invited-handle"),
		now,
	); err != nil {
		t.Fatal(err)
	}

	box, err := sealed.New(bytes.Repeat([]byte{7}, 32), "identity.totp")
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, err := box.Seal(scope.AccountID, []byte("12345678901234567890"))
	if err != nil {
		t.Fatal(err)
	}

	record.AccountID = scope.AccountID
	record.EnrollmentVersion = scope.AuthVersion
	record.Ciphertext = ciphertext

	return store, replica, pool, owner, scope, record, now
}

func TestPostgresInvitedMFAActivationIsAtomicAcrossPools(t *testing.T) {
	store, replica, pool, _, scope, record, now := invitedSQLFixture(t)

	if err := store.SavePendingTOTP(t.Context(), scope, record); err != nil {
		t.Fatal("verified invited password scope could not stage its first MFA", err)
	}

	if err := store.SaveRecoveryCodes(
		t.Context(),
		scope,
		nil,
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("setup scope managed recovery credentials", err)
	}

	if err := store.ConsumeTOTP(
		t.Context(),
		scope,
		record.ID,
		now.Unix()/30,
		now,
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("setup scope used factor for normal login", err)
	}

	key := identity.NamedCredential{
		Name:      "first passkey",
		CreatedAt: now,
		Credential: webauthn.Credential{
			ID:              []byte("invited-key"),
			PublicKey:       []byte("public"),
			AttestationType: "none",
		},
	}
	var activated atomic.Int32
	var group sync.WaitGroup
	for index := range 10 {
		group.Go(func() {
			var err error
			if index%2 == 0 {
				err = replica.ConfirmTOTP(t.Context(), scope, record.ID, now.Unix()/30, now)
			} else {
				err = store.SavePersonalCredential(t.Context(), scope, key)
			}

			if err == nil {
				activated.Add(1)
			} else if !errors.Is(err, identity.ErrInvalidCredential) {
				t.Error(err)
			}
		})
	}

	group.Wait()

	account, err := store.Account(t.Context(), scope.AccountID)

	if err != nil || account.Status != identity.AccountActive || account.AuthVersion != 3 ||
		activated.Load() != 1 {
		t.Fatal("first MFA activation was not one-use", err, activated.Load())
	}

	var factors int

	if err := pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM admin_totp WHERE account_id=$1 AND confirmed_at IS NOT NULL)+(SELECT count(*) FROM webauthn_credentials WHERE user_handle=$2)`, scope.AccountID, account.UserHandle).
		Scan(&factors); err != nil ||
		factors != 1 {
		t.Fatal("activation committed no factor or multiple competing factors", err)
	}

	if scope.Allows(account) {
		t.Fatal("setup authority survived first MFA activation")
	}
}

func TestPostgresInvitedMFACannotActivateAfterRevocation(t *testing.T) {
	store, replica, _, owner, scope, record, now := invitedSQLFixture(t)

	if err := store.SavePendingTOTP(t.Context(), scope, record); err != nil {
		t.Fatal(err)
	}

	if err := replica.RevokeAdmin(t.Context(), owner, scope.AccountID); err != nil {
		t.Fatal(err)
	}

	if err := store.ConfirmTOTP(
		t.Context(),
		scope,
		record.ID,
		now.Unix()/30,
		now,
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("revoked invitation activated", err)
	}

	account, err := store.Account(t.Context(), scope.AccountID)

	if err != nil || account.Status != identity.AccountRevoked {
		t.Fatal("revocation lost", err)
	}
}
