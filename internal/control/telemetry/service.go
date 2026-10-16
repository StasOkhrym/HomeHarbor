// Package telemetry owns latest reported runtime observations. It does not
// authorize VPN traffic or turn coordination connectivity into VPN state.
package telemetry

import (
	"context"
	"errors"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/devices"
	"github.com/StasOkhrym/homeharbor/internal/protocol"
)

const (
	ReportInterval = 30 * time.Second
	StaleAfter     = 90 * time.Second
	storeTimeout   = 5 * time.Second
)

var (
	ErrUnauthorized  = errors.New("telemetry subject not authorized")
	ErrStaleReport   = errors.New("telemetry generation or sequence expired")
	ErrInvalidReport = errors.New("invalid telemetry report")
)

type Observation struct {
	ReporterDeviceID string                   `json:"reporter_device_id"`
	ReporterRole     devices.Role             `json:"reporter_role"`
	SubjectDeviceID  string                   `json:"subject_device_id"`
	Generation       uint64                   `json:"generation"`
	Sequence         uint64                   `json:"sequence"`
	RuntimeID        string                   `json:"runtime_id"`
	State            protocol.RuntimeState    `json:"state"`
	AppliedRevision  uint64                   `json:"applied_revision"`
	ObservedAt       time.Time                `json:"observed_at"`
	Sample           protocol.PeerObservation `json:"sample"`
}

func (o Observation) CurrentState(now time.Time) string {
	age := now.Sub(o.ObservedAt)
	if o.ObservedAt.IsZero() || age < 0 || age >= StaleAfter {
		return "unknown"
	}

	return string(o.State)
}

type Repository interface {
	Begin(context.Context, string, time.Time) (uint64, error)
	Record(context.Context, string, devices.Role, protocol.TelemetryReport, time.Time) error
}
type (
	Authorizer func(context.Context, devices.Device, string) (bool, error)
	Service    struct {
		store     Repository
		authorize Authorizer
		now       func() time.Time
	}
)

// Session's reporter is private: callers obtain it only through Begin after
// device authentication. Wire payloads cannot replace the source identity.
type Session struct {
	Generation uint64
	reporter   devices.Device
}

func NewService(store Repository, authorize Authorizer, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}

	return &Service{store: store, authorize: authorize, now: now}
}

func (s *Service) Begin(ctx context.Context, device devices.Device) (Session, error) {
	if device.ID == "" || device.Status != devices.StatusActive ||
		(device.Role != devices.RoleClient && device.Role != devices.RoleGateway) {
		return Session{}, ErrUnauthorized
	}

	bounded, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()

	generation, err := s.store.Begin(bounded, device.ID, s.now().UTC())
	if err != nil {
		return Session{}, err
	}

	// Retain only the public principal, never bearer/hash/key material.
	return Session{
		Generation: generation,
		reporter:   devices.Device{ID: device.ID, Role: device.Role, Status: device.Status},
	}, nil
}

func (s *Service) Report(
	ctx context.Context,
	session Session,
	report protocol.TelemetryReport,
) error {
	if session.Generation == 0 || report.Generation != session.Generation {
		return ErrStaleReport
	}
	if report.Validate() != nil {
		return ErrInvalidReport
	}

	now := s.now().UTC()
	bounded, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()

	self := false
	for _, sample := range report.Observations {
		if sample.LastHandshakeUnix > now.Add(5*time.Minute).Unix() {
			return ErrInvalidReport
		}
		if sample.DeviceID == session.reporter.ID {
			self = true
			continue
		}
		if session.reporter.Role != devices.RoleGateway || s.authorize == nil {
			return ErrUnauthorized
		}

		allowed, err := s.authorize(bounded, session.reporter, sample.DeviceID)
		if err != nil {
			return err
		}
		if !allowed {
			return ErrUnauthorized
		}
	}

	if !self {
		return ErrInvalidReport
	}

	return s.store.Record(bounded, session.reporter.ID, session.reporter.Role, report, now)
}
