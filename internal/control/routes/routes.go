// Package routes is the public domain name for gateway advertisements and
// split-DNS routes. The aliases keep the current storage implementation
// compatible while callers move away from the ambiguous network package.
// Package routes is the public module boundary for advertised LAN routes and
// split-DNS settings. The type aliases keep compatibility with the first MVP
// schema while callers stop depending on the legacy package name.
package routes

import (
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sokhrym/go-tunnels/internal/control/network"
)

type (
	Status               = network.Status
	Advertisement        = network.Advertisement
	AdvertisementRequest = network.AdvertisementRequest
	Store                = network.Store
	Service              = network.Service
	MemoryStore          = network.MemoryStore
	PostgresStore        = network.PostgresStore
)

const (
	StatusPending  = network.StatusPending
	StatusApproved = network.StatusApproved
	StatusRejected = network.StatusRejected
)

var ErrAdvertisementNotFound = network.ErrAdvertisementNotFound

func NewService(store Store, now func() time.Time) *Service { return network.NewService(store, now) }
func NewMemoryStore() *MemoryStore                          { return network.NewMemoryStore() }
func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore    { return network.NewPostgresStore(pool) }
