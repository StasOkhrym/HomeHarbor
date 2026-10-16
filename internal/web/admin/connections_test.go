package admin

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/devices"
	"github.com/StasOkhrym/homeharbor/internal/control/telemetry"
	"github.com/StasOkhrym/homeharbor/internal/protocol"
)

type connectionReader struct {
	rows []telemetry.Observation
	err  error
}

func (r connectionReader) Latest(context.Context, int) ([]telemetry.Observation, error) {
	return r.rows, r.err
}

func TestConnectionsKeepsStaleAndMissingSeparateFromStopped(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	reader := connectionReader{rows: []telemetry.Observation{
		{
			ReporterDeviceID: "stopped",
			SubjectDeviceID:  "stopped",
			State:            protocol.RuntimeStopped,
			ObservedAt:       now,
			Sample: protocol.PeerObservation{
				DeviceID:          "stopped",
				CountersAvailable: true,
			},
		},
		{
			ReporterDeviceID: "stale",
			SubjectDeviceID:  "stale",
			State:            protocol.RuntimeRunning,
			ObservedAt:       now.Add(-91 * time.Second),
			Sample:           protocol.PeerObservation{DeviceID: "stale"},
		},
	}}
	list := []devices.Device{
		{ID: "stopped", Name: "Kitchen Mac"},
		{ID: "stale", Name: "Old report"},
		{ID: "missing", Name: "Legacy phone"},
	}

	view, status := LoadConnections(
		t.Context(),
		reader,
		list,
		url.Values{},
		func() time.Time { return now },
	)

	if status != 200 || !view.Ready || len(view.Rows) != 3 {
		t.Fatalf("status=%d view=%+v", status, view)
	}

	byID := map[string]ConnectionRow{}
	for _, row := range view.Rows {
		byID[row.DeviceID] = row
	}

	if byID["stopped"].State != "stopped" || byID["stopped"].Received != "0 B" ||
		byID["stopped"].DeviceName != "Kitchen Mac" {
		t.Fatalf("explicit stop/zero lost: %+v", byID["stopped"])
	}

	for _, id := range []string{"stale", "missing"} {
		if byID[id].State != "unknown" || byID[id].Received != "—" {
			t.Fatalf("unobserved status/counter invented: %+v", byID[id])
		}
	}
}

func TestConnectionsUnavailableIsNotEmpty(t *testing.T) {
	view, status := LoadConnections(
		t.Context(),
		connectionReader{err: errors.New("SECRET_DATABASE_ERROR")},
		nil,
		url.Values{},
		time.Now,
	)

	if status != http.StatusServiceUnavailable || view.Ready || view.Error == "" ||
		view.Error == "SECRET_DATABASE_ERROR" {
		t.Fatalf("unavailable misrepresented: status=%d view=%+v", status, view)
	}
}

func TestConnectionsFilterIncludesGatewayPerspectiveWithoutAddingCounters(t *testing.T) {
	now := time.Now()
	reader := connectionReader{rows: []telemetry.Observation{
		{
			ReporterDeviceID: "gateway",
			ReporterRole:     devices.RoleGateway,
			SubjectDeviceID:  "phone",
			State:            protocol.RuntimeRunning,
			ObservedAt:       now,
			Sample: protocol.PeerObservation{
				DeviceID:          "phone",
				CountersAvailable: true,
				RXBytes:           1024,
				TXBytes:           2048,
				Path:              protocol.PathRelay,
				Endpoint:          "127.0.0.1:51820",
			},
		},
		{
			ReporterDeviceID: "phone",
			ReporterRole:     devices.RoleClient,
			SubjectDeviceID:  "phone",
			State:            protocol.RuntimeRunning,
			ObservedAt:       now,
			Sample: protocol.PeerObservation{
				DeviceID:          "phone",
				CountersAvailable: true,
				RXBytes:           2048,
				TXBytes:           1024,
			},
		},
	}}

	view, status := LoadConnections(
		t.Context(),
		reader,
		[]devices.Device{
			{ID: "gateway", Name: "Home gateway"},
			{ID: "phone", Name: "Olena's iPhone"},
		},
		url.Values{"device_id": {"phone"}},
		func() time.Time { return now },
	)

	if status != 200 || len(view.Rows) != 2 {
		t.Fatalf("status=%d rows=%+v", status, view.Rows)
	}
	if view.Rows[0].ReporterName != "Home gateway" || view.Rows[0].Received != "1.0 KiB" ||
		view.Rows[1].Received != "2.0 KiB" {
		t.Fatalf("perspective counters merged/lost: %+v", view.Rows)
	}
}

func TestConnectionsGatewayObservationNeverInventsClientRuntime(t *testing.T) {
	now := time.Now()
	reader := connectionReader{
		rows: []telemetry.Observation{
			{
				ReporterDeviceID: "gateway",
				ReporterRole:     devices.RoleGateway,
				SubjectDeviceID:  "phone",
				State:            protocol.RuntimeRunning,
				ObservedAt:       now,
				Sample:           protocol.PeerObservation{DeviceID: "phone"},
			},
		},
	}

	view, status := LoadConnections(
		t.Context(),
		reader,
		[]devices.Device{{ID: "gateway", Name: "Home gateway"}, {ID: "phone", Name: "iPhone"}},
		url.Values{"device_id": {"phone"}},
		func() time.Time { return now },
	)

	if status != 200 || len(view.Rows) != 2 {
		t.Fatalf("missing separate self state: status=%d rows=%+v", status, view.Rows)
	}
	if view.Rows[0].StateLabel != "Reporter: Runtime running" || view.Rows[1].State != "unknown" ||
		view.Rows[1].Source != "No self report" {
		t.Fatalf("gateway state became client runtime: %+v", view.Rows)
	}
}
