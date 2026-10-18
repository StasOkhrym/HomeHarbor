package identity

import (
	"context"
	"errors"
	"math"
	"time"
)

// The sole owner retains an immutable account ID and the existing passkey user
// handle. Account IDs are public identifiers, never authentication credentials.
const OwnerAccountID = "00000000-0000-4000-8000-000000000001"

type Role string

const (
	RoleOwner Role = "owner"
	RoleAdmin Role = "admin"
)

type AccountStatus string

const (
	AccountSetup   AccountStatus = "setup"
	AccountActive  AccountStatus = "active"
	AccountInvited AccountStatus = "invited"
	AccountRevoked AccountStatus = "revoked"
)

type SessionPurpose string

const (
	SessionAdmin      SessionPurpose = "admin"
	SessionMigration  SessionPurpose = "migration"
	SessionEnrollment SessionPurpose = "enrollment"
)

type Account struct {
	ID              string        `json:"id"`
	Email           string        `json:"email,omitempty"`
	Role            Role          `json:"role"`
	Status          AccountStatus `json:"status"`
	AuthVersion     uint64        `json:"auth_version"`
	PasswordHash    string        `json:"-"`
	UserHandle      []byte        `json:"-"`
	EmailVerifiedAt *time.Time    `json:"email_verified_at,omitempty"`
	CreatedAt       time.Time     `json:"created_at"`
}

// AccountSubject is a safe operation result for rendering/audit attribution.
// It contains no proof, role, password or authority and cannot admit a session.
type AccountSubject struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

func (a Account) Subject() AccountSubject { return AccountSubject{ID: a.ID, Email: a.Email} }

// Principal is derived from current durable account authority and an admitted
// opaque session. Neither an audit context nor a client-supplied role can make it.
type Principal struct {
	AccountID       string
	Email           string
	Role            Role
	Purpose         SessionPurpose
	Method          string
	AuthVersion     uint64
	AuthenticatedAt time.Time
}

func (p Principal) CanManageNetwork() bool {
	return p.Purpose == SessionAdmin && (p.Role == RoleOwner || p.Role == RoleAdmin)
}

func (p Principal) CanManageAccounts() bool {
	return p.Purpose == SessionAdmin && p.Role == RoleOwner
}

// Principal does not read the clock or Redis. Its caller checks session expiry
// and loads this account from SQL on every admission, including across replicas.
func (a Account) Principal(s Session) (Principal, error) {
	invalid := func() (Principal, error) { return Principal{}, ErrInvalidCredential }
	if a.ID == "" || s.AccountID != a.ID || a.AuthVersion == 0 || a.AuthVersion > math.MaxInt64 ||
		s.AuthVersion != a.AuthVersion ||
		s.RevokedAt != nil ||
		s.CreatedAt.IsZero() ||
		!s.ExpiresAt.After(s.CreatedAt) {
		return invalid()
	}
	if a.Role != RoleOwner && a.Role != RoleAdmin {
		return invalid()
	}
	if a.Role == RoleOwner && a.ID != OwnerAccountID {
		return invalid()
	}

	switch s.Method {
	case "passkey", "totp", "recovery":
	default:
		return invalid()
	}

	switch s.Purpose {
	case SessionAdmin:
		if a.Status != AccountActive || a.Email == "" || a.PasswordHash == "" {
			return invalid()
		}
	case SessionMigration:
		if a.Status != AccountSetup || a.Role != RoleOwner || a.ID != OwnerAccountID ||
			s.Method == "totp" ||
			s.ExpiresAt.Sub(s.CreatedAt) > 5*time.Minute {
			return invalid()
		}
	default:
		return invalid()
	}

	return Principal{
		AccountID:       a.ID,
		Email:           a.Email,
		Role:            a.Role,
		Purpose:         s.Purpose,
		Method:          s.Method,
		AuthVersion:     a.AuthVersion,
		AuthenticatedAt: s.CreatedAt,
	}, nil
}

type principalContextKey struct{}

func WithPrincipal(ctx context.Context, principal Principal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, principal)
}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(principalContextKey{}).(Principal)
	return principal, ok
}

func readAccount(ctx context.Context, reader AccountReader, id string) (Account, error) {
	if id == "" {
		return Account{}, ErrInvalidCredential
	}
	if reader == nil {
		return Account{}, ErrSecurityStateUnavailable
	}

	operation, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	account, err := reader.Account(operation, id)
	if errors.Is(err, ErrInvalidCredential) {
		return Account{}, ErrInvalidCredential
	}
	if err != nil {
		return Account{}, ErrSecurityStateUnavailable
	}
	if account.ID != id {
		return Account{}, ErrInvalidCredential
	}

	return account, nil
}

// AccountScope is a requested operation scope, not an authenticated Principal.
// Full operations bind the auth-version from the password/preauth proof.
type (
	AccountScope struct {
		AccountID   string
		AuthVersion uint64
		Purpose     SessionPurpose
	}
	RecoveryUse struct {
		Scope  AccountScope
		Hash   [32]byte `json:"-"`
		UsedAt time.Time
	}
)

func (scope AccountScope) Allows(account Account) bool {
	if scope.AccountID != account.ID || scope.AuthVersion == 0 ||
		scope.AuthVersion != account.AuthVersion {
		return false
	}

	switch scope.Purpose {
	case SessionAdmin:
		return account.Status == AccountActive &&
			(account.Role == RoleOwner || account.Role == RoleAdmin)
	case SessionEnrollment:
		return account.Status == AccountInvited && account.Role == RoleAdmin &&
			account.EmailVerifiedAt != nil &&
			account.PasswordHash != "" &&
			account.Email != ""
	case SessionMigration:
		return account.ID == OwnerAccountID && account.Role == RoleOwner &&
			account.Status == AccountSetup
	default:
		return false
	}
}

// AccountSummary is owner-visible directory data, never an authority or a
// credential record. Keeping it distinct prevents accidental secret projection.
type AccountSummary struct {
	ID            string        `json:"id"`
	Email         string        `json:"email"`
	Role          Role          `json:"role"`
	Status        AccountStatus `json:"status"`
	EmailVerified bool          `json:"email_verified"`
	CreatedAt     time.Time     `json:"created_at"`
}
