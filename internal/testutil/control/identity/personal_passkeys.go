package identity

import (
	"bytes"
	"context"
	"encoding/base64"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	domain "github.com/StasOkhrym/homeharbor/internal/control/identity"
)

func (s *Repository) SavePersonalCredential(
	ctx context.Context,
	scope domain.AccountScope,
	value domain.NamedCredential,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	account := s.accounts[scope.AccountID]
	if (scope.Purpose != domain.SessionAdmin && scope.Purpose != domain.SessionEnrollment) ||
		!scope.Allows(account) {
		return domain.ErrInvalidCredential
	}

	handle := string(account.UserHandle)
	if len(s.credentials[handle]) >= domain.MaxPasskeys {
		return domain.ErrFactorLimit
	}

	for _, credentials := range s.credentials {
		for _, existing := range credentials {
			if bytes.Equal(existing.ID, value.Credential.ID) {
				return domain.ErrInvalidCredential
			}
		}
	}

	s.credentials[handle] = append(s.credentials[handle], cloneCredential(value.Credential))
	if s.passkeyInfo == nil {
		s.passkeyInfo = make(map[string]domain.PasskeyInfo)
	}

	s.passkeyInfo[string(value.Credential.ID)] = domain.PasskeyInfo{
		Name:      value.Name,
		CreatedAt: value.CreatedAt,
	}
	if scope.Purpose == domain.SessionEnrollment {
		account.Status = domain.AccountActive
	}

	account.AuthVersion++
	s.accounts[scope.AccountID] = account

	return nil
}

func (s *Repository) UpdatePersonalCredential(
	ctx context.Context,
	scope domain.AccountScope,
	credential webauthn.Credential,
	now time.Time,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	account := s.accounts[scope.AccountID]
	if scope.Purpose != domain.SessionAdmin || !scope.Allows(account) {
		return domain.ErrInvalidCredential
	}

	for index, stored := range s.credentials[string(account.UserHandle)] {
		if bytes.Equal(stored.ID, credential.ID) {
			if stored.Authenticator.SignCount > 0 &&
				credential.Authenticator.SignCount <= stored.Authenticator.SignCount {
				return domain.ErrInvalidCredential
			}

			s.credentials[string(account.UserHandle)][index] = cloneCredential(credential)
			if s.passkeyInfo == nil {
				s.passkeyInfo = make(map[string]domain.PasskeyInfo)
			}

			info := s.passkeyInfo[string(credential.ID)]
			info.LastUsedAt = &now
			s.passkeyInfo[string(credential.ID)] = info

			return nil
		}
	}

	return domain.ErrInvalidCredential
}

func (s *Repository) FactorState(
	ctx context.Context,
	scope domain.AccountScope,
) (domain.FactorState, error) {
	if err := ctx.Err(); err != nil {
		return domain.FactorState{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	account := s.accounts[scope.AccountID]
	if scope.Purpose != domain.SessionAdmin || !scope.Allows(account) {
		return domain.FactorState{}, domain.ErrInvalidCredential
	}

	state := domain.FactorState{Passkeys: []domain.PasskeyInfo{}}
	for _, credential := range s.credentials[string(account.UserHandle)] {
		info := s.passkeyInfo[string(credential.ID)]
		info.ID = base64.RawURLEncoding.EncodeToString(credential.ID)
		if info.Name == "" {
			info.Name = "Passkey"
		}

		if info.LastUsedAt != nil {
			used := *info.LastUsedAt
			info.LastUsedAt = &used
		}

		state.Passkeys = append(state.Passkeys, info)
	}

	if totp, ok := s.totp[scope.AccountID]; ok {
		state.TOTP = totp.ConfirmedAt != nil
	}

	for _, code := range s.recoveryCodes[scope.AccountID] {
		if code.UsedAt == nil {
			state.RecoveryCodesRemaining++
		}
	}

	return state, nil
}

func (s *Repository) RemovePasskey(
	ctx context.Context,
	scope domain.AccountScope,
	id []byte,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	account := s.accounts[scope.AccountID]
	if scope.Purpose != domain.SessionAdmin || !scope.Allows(account) {
		return domain.ErrInvalidCredential
	}

	handle := string(account.UserHandle)
	for index, credential := range s.credentials[handle] {
		if bytes.Equal(credential.ID, id) {
			totp := s.totp[scope.AccountID]
			if len(s.credentials[handle]) == 1 && totp.ConfirmedAt == nil {
				return domain.ErrLastMFA
			}

			s.credentials[handle] = append(
				s.credentials[handle][:index],
				s.credentials[handle][index+1:]...)
			delete(s.passkeyInfo, string(id))
			account.AuthVersion++
			s.accounts[scope.AccountID] = account

			return nil
		}
	}

	return domain.ErrInvalidCredential
}
