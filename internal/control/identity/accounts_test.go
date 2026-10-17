package identity

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestAccountPrincipalRequiresPersonalSessionAndLiveAuthority(t *testing.T) {
	now := time.Now().UTC()
	account := Account{
		ID:           "admin-a",
		Role:         RoleAdmin,
		Status:       AccountActive,
		AuthVersion:  3,
		Email:        "admin@example.test",
		PasswordHash: "private-password-hash",
	}
	session := Session{
		AccountID:   account.ID,
		AuthVersion: 3,
		Purpose:     SessionAdmin,
		Method:      "passkey",
		CreatedAt:   now,
		ExpiresAt:   now.Add(time.Hour),
	}

	principal, err := account.Principal(session)

	if err != nil || principal.AccountID != account.ID || !principal.CanManageNetwork() ||
		principal.CanManageAccounts() {
		t.Fatalf("personal admin authority=%+v err=%v", principal, err)
	}

	for _, kind := range []string{"legacy", "foreign", "old-version", "revoked", "invited", "setup", "unknown-method", "unknown-role", "missing-config"} {
		t.Run(kind, func(t *testing.T) {
			a, s := account, session
			switch kind {
			case "legacy":
				s = Session{CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
			case "foreign":
				s.AccountID = "someone-else"
			case "old-version":
				s.AuthVersion = 2
			case "revoked":
				a.Status = AccountRevoked
			case "invited":
				a.Status = AccountInvited
			case "setup":
				a.Status = AccountSetup
			case "unknown-method":
				s.Method = "email"
			case "unknown-role":
				a.Role = "device"
			case "missing-config":
				a.PasswordHash = ""
			}

			if _, err := a.Principal(s); !errors.Is(err, ErrInvalidCredential) {
				t.Fatalf("invalid authority accepted: %v", err)
			}
		})
	}

	account.Role = RoleOwner
	account.ID = OwnerAccountID
	session.AccountID = OwnerAccountID

	principal, err = account.Principal(session)

	if err != nil || !principal.CanManageAccounts() {
		t.Fatal("active owner lost account management")
	}
}

func TestOwnerMigrationPrincipalCannotManageNetworkOrAccounts(t *testing.T) {
	now := time.Now().UTC()
	owner := Account{ID: OwnerAccountID, Role: RoleOwner, Status: AccountSetup, AuthVersion: 1}
	session := Session{
		AccountID:   owner.ID,
		AuthVersion: 1,
		Purpose:     SessionMigration,
		Method:      "passkey",
		CreatedAt:   now,
		ExpiresAt:   now.Add(5 * time.Minute),
	}

	principal, err := owner.Principal(session)

	if err != nil || principal.Purpose != SessionMigration || principal.CanManageNetwork() ||
		principal.CanManageAccounts() {
		t.Fatalf("legacy proof became full admin: %+v %v", principal, err)
	}

	owner.Status = AccountActive
	owner.Email = "owner@example.test"
	owner.PasswordHash = "hash"

	if _, err := owner.Principal(session); !errors.Is(err, ErrInvalidCredential) {
		t.Fatal("migration session remained usable after activation")
	}
}

func TestAccountCredentialsNeverEnterPublicJSON(t *testing.T) {
	payload, err := json.Marshal(
		Account{
			ID:           "a",
			PasswordHash: "canary-password-hash",
			UserHandle:   []byte("canary-user-handle"),
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(string(payload), "canary") ||
		strings.Contains(string(payload), "password") ||
		strings.Contains(string(payload), "handle") {
		t.Fatalf("credential material serialized: %s", payload)
	}
}
