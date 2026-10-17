package migrations

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	testpostgres "github.com/StasOkhrym/homeharbor/internal/testutil/postgres"
)

func TestPostgresOwnerAccountMigrationPreservesLegacyIdentity(t *testing.T) {
	pool := testpostgres.OpenSchema(t)

	if _, err := pool.Exec(
		t.Context(),
		`CREATE TABLE schema_migrations(name text PRIMARY KEY,applied_at timestamptz NOT NULL DEFAULT now())`,
	); err != nil {
		t.Fatal(err)
	}

	names, err := Names()
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range names {
		if strings.Compare(name, "000016") >= 0 {
			continue
		}

		sql, err := files.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := pool.Exec(t.Context(), string(sql)); err != nil {
			t.Fatalf("legacy schema %s: %v", name, err)
		}

		if _, err := pool.Exec(
			t.Context(),
			`INSERT INTO schema_migrations(name)VALUES($1)`,
			name,
		); err != nil {
			t.Fatal(err)
		}
	}

	handle := []byte("homeharbor-admin-v1")
	credential := []byte("legacy-public-credential")
	payload := []byte(`{"ID":"bGVnYWN5","PublicKey":"cHVibGlj","AttestationType":"none"}`)

	if _, err := pool.Exec(
		t.Context(),
		`INSERT INTO webauthn_credentials(credential_id,public_key,attestation_type,user_handle,credential_data,sign_count)VALUES($1,$2,'none',$3,$4,7)`,
		credential,
		[]byte("public-key"),
		handle,
		payload,
	); err != nil {
		t.Fatal(err)
	}

	codeHash := sha256.Sum256([]byte("legacy-single-use-code"))

	if _, err := pool.Exec(
		t.Context(),
		`INSERT INTO recovery_codes(code_hash)VALUES($1)`,
		codeHash[:],
	); err != nil {
		t.Fatal(err)
	}

	if err := Up(t.Context(), pool); err != nil {
		t.Fatal(err)
	}

	if err := Up(t.Context(), pool); err != nil {
		t.Fatal(err)
	}

	var id, role, status string
	var ownerHandle, storedHandle, storedID []byte
	var version uint64

	if err := pool.QueryRow(t.Context(), `SELECT account_id,role,status,auth_version,user_handle FROM admin_accounts`).
		Scan(&id, &role, &status, &version, &ownerHandle); err != nil {
		t.Fatal(err)
	}

	if id != "00000000-0000-4000-8000-000000000001" || role != "owner" || status != "setup" ||
		version != 1 ||
		!bytes.Equal(ownerHandle, handle) {
		t.Fatal("legacy owner identity or restricted state changed")
	}

	var signCount int64
	var storedPayload []byte

	if err := pool.QueryRow(t.Context(), `SELECT user_handle,credential_id,credential_data,sign_count FROM webauthn_credentials`).
		Scan(&storedHandle, &storedID, &storedPayload, &signCount); err != nil {
		t.Fatal(err)
	}

	var originalJSON, migratedJSON any

	if json.Unmarshal(payload, &originalJSON) != nil ||
		json.Unmarshal(storedPayload, &migratedJSON) != nil ||
		!reflect.DeepEqual(originalJSON, migratedJSON) {
		t.Fatal("migration replaced credential payload")
	}
	if !bytes.Equal(storedHandle, handle) || !bytes.Equal(storedID, credential) || signCount != 7 {
		t.Fatal("migration replaced existing passkey identity/counter")
	}

	var codeOwner string

	if err := pool.QueryRow(t.Context(), `SELECT account_id FROM recovery_codes WHERE code_hash=$1`, codeHash[:]).
		Scan(&codeOwner); err != nil ||
		codeOwner != id {
		t.Fatalf("recovery ownership lost: %s %v", codeOwner, err)
	}

	for _, statement := range []string{
		`UPDATE admin_accounts SET status='revoked' WHERE role='owner'`,
		`UPDATE admin_accounts SET role='admin' WHERE role='owner'`,
		`UPDATE admin_accounts SET auth_version=0 WHERE role='owner'`,
	} {
		if _, err := pool.Exec(t.Context(), statement); err == nil {
			t.Fatalf("owner invariant was not enforced: %s", statement)
		}
	}
}
