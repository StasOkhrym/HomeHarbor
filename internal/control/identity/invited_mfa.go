package identity

import "context"

func (s *MFAService) invitedAccount(ctx context.Context, factor FactorContext) (Account, error) {
	if factor.Binding == ([32]byte{}) || factor.Purpose != SessionEnrollment {
		return Account{}, ErrInvalidCredential
	}

	account, err := readAccount(ctx, s.store, factor.AccountID)
	if err != nil {
		return Account{}, err
	}
	if !factor.Allows(account) {
		return Account{}, ErrInvalidCredential
	}

	return account, nil
}

func (s *MFAService) BeginInvitedTOTP(
	ctx context.Context,
	factor FactorContext,
) (TOTPEnrollment, error) {
	account, err := s.invitedAccount(ctx, factor)
	if err != nil {
		return TOTPEnrollment{}, err
	}

	return s.beginTOTP(ctx, factor.AccountScope, account)
}

func (s *MFAService) ConfirmInvitedTOTP(
	ctx context.Context,
	factor FactorContext,
	code string,
) error {
	if _, err := s.invitedAccount(ctx, factor); err != nil {
		return err
	}

	return s.confirmTOTP(ctx, factor.AccountScope, code)
}

func (s *MFAService) BeginInvitedPasskey(
	ctx context.Context,
	factor FactorContext,
	name string,
) (BeginCeremony, error) {
	if _, err := s.invitedAccount(ctx, factor); err != nil {
		return BeginCeremony{}, err
	}

	return s.beginPasskeyEnrollment(ctx, factor.AccountScope, name, factor.Binding)
}

func (s *MFAService) FinishInvitedPasskey(
	ctx context.Context,
	factor FactorContext,
	id string,
	response []byte,
) error {
	if _, err := s.invitedAccount(ctx, factor); err != nil {
		return err
	}

	return s.passkeys.finishPersonalEnrollment(
		ctx,
		factor.AccountScope,
		id,
		response,
		factor.Binding,
	)
}
