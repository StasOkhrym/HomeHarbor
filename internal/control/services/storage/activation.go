package storage

import (
	"context"

	"github.com/jackc/pgx/v5"
)

type Transaction struct{ tx pgx.Tx }

func Bind(tx pgx.Tx) *Transaction { return &Transaction{tx: tx} }
func (s *Transaction) AddDevice(ctx context.Context, profileID, deviceID string) error {
	_, err := s.tx.Exec(ctx, `INSERT INTO access_profile_devices(profile_id,device_id) VALUES($1,$2)`, profileID, deviceID)
	return err
}
