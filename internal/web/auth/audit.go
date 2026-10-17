package auth

import (
	"context"

	"github.com/StasOkhrym/homeharbor/internal/control/audit"
	"github.com/StasOkhrym/homeharbor/internal/control/identity"
)

// Called only after the owner-only legacy ceremony or recovery proof succeeds.
// Possession establishes this actor; it does not establish password/MFA login.
func legacyProofAuditContext(ctx context.Context, method string) context.Context {
	facts := audit.FromContext(ctx)
	facts.ActorType, facts.ActorID, facts.ActorName = "admin", identity.OwnerAccountID, ""
	facts.Authentication = method

	return audit.WithContext(ctx, facts)
}

func principalAuditContext(ctx context.Context, principal identity.Principal) context.Context {
	facts := audit.FromContext(ctx)
	facts.ActorType, facts.ActorID, facts.ActorName = "admin", principal.AccountID, principal.Email
	if principal.Purpose == identity.SessionAdmin {
		facts.Authentication = "password_" + principal.Method
	} else if principal.Method == "passkey" {
		facts.Authentication = "passkey"
	} else {
		facts.Authentication = "identity_proof"
	}

	return audit.WithContext(ctx, facts)
}
