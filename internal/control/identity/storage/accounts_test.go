package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	redisclient "github.com/redis/go-redis/v9"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
	identityredis "github.com/StasOkhrym/homeharbor/internal/control/identity/redis"
	testpostgres "github.com/StasOkhrym/homeharbor/internal/testutil/postgres"
	"github.com/StasOkhrym/homeharbor/migrations"
)

func TestPostgresPersonalCredentialLookupCannotCrossAccounts(t *testing.T) {
	pool := testpostgres.OpenSchema(t)

	if err := migrations.Up(t.Context(), pool); err != nil {
		t.Fatal(err)
	}

	for _, id := range []string{"a", "b"} {
		if _, err := pool.Exec(
			t.Context(),
			`INSERT INTO admin_accounts(account_id,email,role,status,password_hash,user_handle)VALUES($1,$1||'@example.test','admin','active','hash',$2)`,
			id,
			[]byte(id),
		); err != nil {
			t.Fatal(err)
		}
	}

	credential := webauthn.Credential{
		ID:              []byte("owned-a"),
		PublicKey:       []byte("public"),
		AttestationType: "none",
		Authenticator:   webauthn.Authenticator{SignCount: 7},
	}

	payload, err := json.Marshal(credential)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := pool.Exec(
		t.Context(),
		`INSERT INTO webauthn_credentials(credential_id,public_key,attestation_type,transport,sign_count,user_handle,credential_data)VALUES($1,$2,'none','{}',7,$3,$4)`,
		credential.ID,
		credential.PublicKey,
		[]byte("a"),
		payload,
	); err != nil {
		t.Fatal(err)
	}

	store := New(pool)

	if _, err := store.Credential(
		t.Context(),
		[]byte("b"),
		credential.ID,
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatalf("foreign credential lookup: %v", err)
	}

	credentials, err := store.Credentials(t.Context(), []byte("b"))

	if err != nil || len(credentials) != 0 {
		t.Fatalf("foreign credential list: %d %v", len(credentials), err)
	}

	credential.Authenticator.SignCount++

	if err := store.UpdateCredential(
		t.Context(),
		[]byte("b"),
		credential,
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatalf("foreign credential update: %v", err)
	}

	own, err := store.Credential(t.Context(), []byte("a"), credential.ID)

	if err != nil || own.Authenticator.SignCount != 7 {
		t.Fatalf("foreign operation changed owned credential: %+v %v", own, err)
	}
}

func TestPostgresRecoveryCommitRejectsStaleProofWithoutConsumingCode(t *testing.T) {
	pool := testpostgres.OpenSchema(t)

	if err := migrations.Up(t.Context(), pool); err != nil {
		t.Fatal(err)
	}

	store := New(pool)
	scope := identity.AccountScope{
		AccountID:   identity.OwnerAccountID,
		AuthVersion: 1,
		Purpose:     identity.SessionMigration,
	}

	hash := sha256.Sum256([]byte("test-only-recovery"))

	now := time.Now().UTC()

	if err := store.SaveRecoveryCodes(
		t.Context(),
		scope,
		[]identity.RecoveryCode{{Hash: hash, CreatedAt: now}},
	); err != nil {
		t.Fatal(err)
	}

	if _, err := pool.Exec(
		t.Context(),
		`UPDATE admin_accounts SET auth_version=2,status='active',email='owner@example.test',password_hash='hash' WHERE account_id=$1`,
		identity.OwnerAccountID,
	); err != nil {
		t.Fatal(err)
	}

	if err := store.SaveRecoveryCodes(
		t.Context(),
		scope,
		nil,
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatalf("stale replacement admitted: %v", err)
	}

	if err := store.ConsumeRecoveryCode(
		t.Context(),
		identity.RecoveryUse{Scope: scope, Hash: hash, UsedAt: now},
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatalf("stale consumption admitted: %v", err)
	}

	scope.Purpose = identity.SessionAdmin
	scope.AuthVersion = 2

	if err := store.ConsumeRecoveryCode(
		t.Context(),
		identity.RecoveryUse{Scope: scope, Hash: hash, UsedAt: now},
	); err != nil {
		t.Fatalf("rejected operation burned the code: %v", err)
	}
}

func TestPostgresRedisPersonalSessionReadsLiveAuthorityAcrossPools(t *testing.T) {
	endpoint := os.Getenv("TEST_REDIS_URL")
	if endpoint == "" {
		t.Skip("TEST_REDIS_URL required for PostgreSQL/Redis authority integration")
	}

	pool := testpostgres.OpenSchema(t)

	if err := migrations.Up(t.Context(), pool); err != nil {
		t.Fatal(err)
	}

	other, err := pgxpool.NewWithConfig(t.Context(), pool.Config())
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(other.Close)

	options, err := redisclient.ParseURL(endpoint)
	if err != nil {
		t.Fatal(err)
	}

	client := redisclient.NewClient(options)
	t.Cleanup(func() { _ = client.Close() })
	secondClient := redisclient.NewClient(options)
	t.Cleanup(func() { _ = secondClient.Close() })
	prefix := "test:personal-authority:" + uuid.NewString()
	firstSessions, err := identityredis.NewSessions(client, prefix, time.Now, time.Second)
	if err != nil {
		t.Fatal(err)
	}

	secondSessions, err := identityredis.NewSessions(secondClient, prefix, time.Now, time.Second)
	if err != nil {
		t.Fatal(err)
	}

	firstStore, secondStore := New(pool), New(other)
	first := identity.NewService(firstStore, firstSessions, firstStore, time.Now, nil)
	second := identity.NewService(secondStore, secondSessions, secondStore, time.Now, nil)

	if _, err := pool.Exec(
		t.Context(),
		`INSERT INTO admin_accounts(account_id,email,role,status,password_hash,user_handle)VALUES('replica-admin','a@example.test','admin','active','hash','replica-admin')`,
	); err != nil {
		t.Fatal(err)
	}

	request := identity.SessionRequest{
		AccountID:   "replica-admin",
		AuthVersion: 1,
		Purpose:     identity.SessionAdmin,
		Method:      "totp",
		TTL:         time.Hour,
	}

	issued, err := first.CreateSession(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}

	hash := sha256.Sum256([]byte(issued.Token))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		if err := client.Del(ctx, prefix+":browser-session:principal:"+hex.EncodeToString(hash[:])).
			Err(); err != nil {
			t.Error(err)
		}
	})

	principal, err := second.ValidateSession(t.Context(), issued.Token)

	if err != nil || principal.AccountID != request.AccountID || principal.CanManageAccounts() {
		t.Fatalf("cross-replica principal: %+v %v", principal, err)
	}

	if _, err := other.Exec(
		t.Context(),
		`UPDATE admin_accounts SET auth_version=2 WHERE account_id=$1`,
		request.AccountID,
	); err != nil {
		t.Fatal(err)
	}

	if _, err := first.ValidateSession(
		t.Context(),
		issued.Token,
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatalf("SQL epoch change left Redis session authorized: %v", err)
	}

	if _, err := second.CreateSession(
		t.Context(),
		request,
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatalf("stale password proof minted current session: %v", err)
	}

	// Reusing the opaque Redis record with the current epoch isolates status
	// revocation from the independent auth-version rejection just checked.
	stored, err := firstSessions.Session(t.Context(), hash)
	if err != nil {
		t.Fatal(err)
	}

	if err := firstSessions.RevokeSession(t.Context(), hash, time.Now()); err != nil {
		t.Fatal(err)
	}

	stored.AuthVersion = 2

	if err := firstSessions.SaveSession(t.Context(), stored); err != nil {
		t.Fatal(err)
	}

	if _, err := first.ValidateSession(t.Context(), issued.Token); err != nil {
		t.Fatal(err)
	}

	if _, err := other.Exec(
		t.Context(),
		`UPDATE admin_accounts SET status='revoked' WHERE account_id=$1`,
		request.AccountID,
	); err != nil {
		t.Fatal(err)
	}

	if _, err := first.ValidateSession(
		t.Context(),
		issued.Token,
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatalf("cross-pool revocation left session authorized: %v", err)
	}
}

func TestPostgresOwnerPasswordSetupSerializesAgainstReplayAndKeepsCredential(t *testing.T) {
	pool := testpostgres.OpenSchema(t)

	if err := migrations.Up(t.Context(), pool); err != nil {
		t.Fatal(err)
	}

	other, err := pgxpool.NewWithConfig(t.Context(), pool.Config())
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(other.Close)
	store, replica := New(pool), New(other)
	handle := []byte("homeharbor-admin-v1")
	credential := webauthn.Credential{
		ID:              []byte("legacy-owner"),
		PublicKey:       []byte("public"),
		AttestationType: "none",
		Authenticator:   webauthn.Authenticator{SignCount: 7},
	}

	if err := store.SaveBootstrapCredential(t.Context(), handle, credential); err != nil {
		t.Fatal(err)
	}

	scope := identity.AccountScope{
		AccountID:   identity.OwnerAccountID,
		AuthVersion: 1,
		Purpose:     identity.SessionMigration,
	}
	var successes atomic.Int32
	var group sync.WaitGroup
	for range 12 {
		group.Go(func() {
			if err := replica.ConfigureOwner(
				t.Context(),
				scope,
				"owner@example.test",
				"hashed-password",
			); err == nil {
				successes.Add(1)
			} else if !errors.Is(
				err,
				identity.ErrInvalidCredential,
			) {
				t.Error(err)
			}
		})
	}

	group.Wait()

	if successes.Load() != 1 {
		t.Fatalf("owner setup commits=%d", successes.Load())
	}

	owner, err := store.AccountByEmail(t.Context(), "owner@example.test")

	if err != nil || owner.ID != identity.OwnerAccountID || owner.AuthVersion != 2 ||
		owner.Status != identity.AccountActive ||
		owner.PasswordHash != "hashed-password" {
		t.Fatalf("wrong owner authority: %+v %v", owner, err)
	}

	key, err := replica.Credential(t.Context(), handle, credential.ID)

	if err != nil || key.Authenticator.SignCount != 7 || string(key.PublicKey) != "public" {
		t.Fatal("owner setup changed existing key", err)
	}
}

func TestPostgresRedisSessionRevocationFencesBothReplicas(t *testing.T) {
	endpoint := os.Getenv("TEST_REDIS_URL")
	if endpoint == "" {
		t.Skip("TEST_REDIS_URL required for PostgreSQL/Redis authority integration")
	}

	pool := testpostgres.OpenSchema(t)

	if err := migrations.Up(t.Context(), pool); err != nil {
		t.Fatal(err)
	}

	other, err := pgxpool.NewWithConfig(t.Context(), pool.Config())
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(other.Close)

	options, err := redisclient.ParseURL(endpoint)
	if err != nil {
		t.Fatal(err)
	}

	client := redisclient.NewClient(options)
	t.Cleanup(func() { _ = client.Close() })
	secondClient := redisclient.NewClient(options)
	t.Cleanup(func() { _ = secondClient.Close() })
	prefix := "test:personal-authority:" + uuid.NewString()
	firstSessions, err := identityredis.NewSessions(client, prefix, time.Now, time.Second)
	if err != nil {
		t.Fatal(err)
	}

	secondSessions, err := identityredis.NewSessions(secondClient, prefix, time.Now, time.Second)
	if err != nil {
		t.Fatal(err)
	}

	firstStore, secondStore := New(pool), New(other)
	first := identity.NewService(firstStore, firstSessions, firstStore, time.Now, nil)
	second := identity.NewService(secondStore, secondSessions, secondStore, time.Now, nil)

	if _, err := pool.Exec(
		t.Context(),
		`INSERT INTO admin_accounts(account_id,email,role,status,password_hash,user_handle)VALUES('replica-admin','a@example.test','admin','active','hash','replica-admin')`,
	); err != nil {
		t.Fatal(err)
	}

	request := identity.SessionRequest{
		AccountID:   "replica-admin",
		AuthVersion: 1,
		Purpose:     identity.SessionAdmin,
		Method:      "totp",
		TTL:         time.Hour,
	}

	issued, err := first.CreateSession(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}

	remember := func(token string) {
		hash := sha256.Sum256([]byte(token))
		key := prefix + ":browser-session:principal:" + hex.EncodeToString(hash[:])
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			if err := client.Del(ctx, key).Err(); err != nil {
				t.Error(err)
			}
		})
	}

	remember(issued.Token)

	another, err := second.CreateSession(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}

	remember(another.Token)

	if _, err := pool.Exec(
		t.Context(),
		`INSERT INTO admin_accounts(account_id,email,role,status,password_hash,user_handle)VALUES('unrelated-admin','other@example.test','admin','active','hash','unrelated-admin')`,
	); err != nil {
		t.Fatal(err)
	}

	otherRequest := request
	otherRequest.AccountID = "unrelated-admin"

	unrelated, err := first.CreateSession(t.Context(), otherRequest)
	if err != nil {
		t.Fatal(err)
	}

	remember(unrelated.Token)
	scope := identity.AccountScope{
		AccountID:   request.AccountID,
		AuthVersion: 1,
		Purpose:     identity.SessionAdmin,
	}
	restricted := scope
	restricted.Purpose = identity.SessionMigration

	if err := secondStore.RevokeSessions(
		t.Context(),
		restricted,
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("restricted scope revoked sessions", err)
	}

	if err := secondStore.RevokeSessions(t.Context(), scope); err != nil {
		t.Fatal(err)
	}

	for _, service := range []*identity.Service{first, second} {
		for _, token := range []string{issued.Token, another.Token} {
			if _, err := service.ValidateSession(
				t.Context(),
				token,
			); !errors.Is(
				err,
				identity.ErrInvalidCredential,
			) {
				t.Fatal("another replica admitted revoked session", err)
			}
		}
	}

	hash := sha256.Sum256([]byte(issued.Token))

	if _, err := firstSessions.Session(t.Context(), hash); err != nil {
		t.Fatal("revocation unexpectedly depended on deleting Redis records", err)
	}

	if _, err := second.ValidateSession(t.Context(), unrelated.Token); err != nil {
		t.Fatal("another account's session revoked", err)
	}

	if err := firstStore.RevokeSessions(
		t.Context(),
		scope,
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("old scope repeated session revocation", err)
	}

	if _, err := first.CreateSession(
		t.Context(),
		request,
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("stale proof recreated a session", err)
	}

	account, err := firstStore.Account(t.Context(), request.AccountID)

	if err != nil || account.AuthVersion != 2 || account.Status != identity.AccountActive ||
		account.PasswordHash != "hash" {
		t.Fatal("revocation changed account authentication", err)
	}

	request.AuthVersion = 2

	fresh, err := first.CreateSession(t.Context(), request)
	if err != nil {
		t.Fatal("fresh current proof cannot create session", err)
	}

	remember(fresh.Token)

	if _, err := second.ValidateSession(t.Context(), fresh.Token); err != nil {
		t.Fatal("fresh session unavailable across replicas", err)
	}
}
