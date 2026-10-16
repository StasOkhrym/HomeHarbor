package admin

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/devices"
	"github.com/StasOkhrym/homeharbor/internal/control/telemetry"
)

type ConnectionReader interface {
	Latest(context.Context, int) ([]telemetry.Observation, error)
}

type Connections struct {
	Ready         bool
	Error         string
	DeviceID      string
	DeviceOptions []ActivityOption
	Rows          []ConnectionRow
}

type ConnectionRow struct {
	DeviceID         string
	DeviceName       string
	ReporterID       string
	ReporterName     string
	CredentialStatus devices.Status
	State            string
	StateLabel       string
	Source           string
	Freshness        string
	ObservedAt       time.Time
	AppliedRevision  uint64
	Handshake        string
	Endpoint         string
	Transport        string
	Received         string
	Sent             string
}

func LoadConnections(
	ctx context.Context,
	reader ConnectionReader,
	list []devices.Device,
	values url.Values,
	clock func() time.Time,
) (Connections, int) {
	view := Connections{DeviceID: strings.TrimSpace(values.Get("device_id"))}
	if len(view.DeviceID) > 128 {
		view.Error = "Choose a valid device filter"
		return view, http.StatusBadRequest
	}
	if reader == nil {
		view.Error = "Runtime reports are not configured"
		return view, http.StatusServiceUnavailable
	}

	observations, err := reader.Latest(ctx, 200)
	if err != nil {
		view.Error = "Runtime reports could not be loaded"
		return view, http.StatusServiceUnavailable
	}

	if clock == nil {
		clock = time.Now
	}

	// A report can commit while the read is in flight. Measure freshness after
	// reading so a new report is not accidentally classified as future-dated.
	now := clock()
	names := map[string]devices.Device{}
	view.DeviceOptions = []ActivityOption{{Value: "", Label: "All devices"}}
	selected := view.DeviceID == ""
	for _, device := range list {
		names[device.ID] = device
		view.DeviceOptions = append(
			view.DeviceOptions,
			ActivityOption{Value: device.ID, Label: device.Name},
		)
		selected = selected || view.DeviceID == device.ID
	}

	if !selected {
		view.DeviceOptions = append(
			view.DeviceOptions,
			ActivityOption{Value: view.DeviceID, Label: view.DeviceID},
		)
	}

	selfReports := map[string]bool{}
	name := func(id string) string {
		if value := names[id].Name; value != "" {
			return value
		}

		return "Unnamed device"
	}
	for _, observation := range observations {
		self := observation.ReporterDeviceID == observation.SubjectDeviceID
		if self {
			selfReports[observation.SubjectDeviceID] = true
		}

		if view.DeviceID != "" && observation.SubjectDeviceID != view.DeviceID &&
			observation.ReporterDeviceID != view.DeviceID {
			continue
		}

		state := observation.CurrentState(now)
		row := ConnectionRow{
			DeviceID:         observation.SubjectDeviceID,
			DeviceName:       name(observation.SubjectDeviceID),
			ReporterID:       observation.ReporterDeviceID,
			ReporterName:     name(observation.ReporterDeviceID),
			CredentialStatus: names[observation.SubjectDeviceID].Status,
			State:            state,
			StateLabel:       connectionStateLabel(state),
			Source:           "Self report",
			Freshness:        "Recent report",
			ObservedAt:       observation.ObservedAt,
			AppliedRevision:  observation.AppliedRevision,
			Handshake:        "Not reported",
			Endpoint:         observation.Sample.Endpoint,
			Transport:        "Not reported",
			Received:         "—",
			Sent:             "—",
		}
		if !self {
			row.Source = "Gateway peer observation"
			row.StateLabel = "Reporter: " + row.StateLabel
		}

		if state == "unknown" {
			row.Freshness = "Stale report · current state unknown"
		}

		if observation.Sample.CountersAvailable {
			row.Received = byteCount(observation.Sample.RXBytes)
			row.Sent = byteCount(observation.Sample.TXBytes)
		}

		if observation.Sample.LastHandshakeUnix > 0 {
			row.Handshake = time.Unix(observation.Sample.LastHandshakeUnix, 0).
				UTC().
				Format("02 Jan 2006, 15:04:05 UTC")
		}

		switch observation.Sample.Path {
		case "direct":
			row.Transport = "Direct"
		case "relay":
			row.Transport = "Relay"
		}

		view.Rows = append(view.Rows, row)
	}

	for _, device := range list {
		if selfReports[device.ID] || view.DeviceID != "" && device.ID != view.DeviceID {
			continue
		}

		view.Rows = append(
			view.Rows,
			ConnectionRow{
				DeviceID:         device.ID,
				DeviceName:       name(device.ID),
				ReporterID:       device.ID,
				ReporterName:     name(device.ID),
				CredentialStatus: device.Status,
				State:            "unknown",
				StateLabel:       "State unknown",
				Source:           "No self report",
				Freshness:        "Not reported",
				Handshake:        "Not reported",
				Transport:        "Not reported",
				Received:         "—",
				Sent:             "—",
			},
		)
	}

	view.Ready = true

	return view, http.StatusOK
}

func connectionStateLabel(state string) string {
	switch state {
	case "running":
		return "Runtime running"
	case "starting":
		return "Runtime starting"
	case "stopped":
		return "Runtime stopped"
	case "failed":
		return "Runtime reported an error"
	default:
		return "State unknown"
	}
}

func byteCount(value uint64) string {
	if value < 1024 {
		return fmt.Sprintf("%d B", value)
	}

	count := float64(value)
	for _, unit := range []string{"KiB", "MiB", "GiB", "TiB", "PiB", "EiB"} {
		count /= 1024
		if count < 1024 || unit == "EiB" {
			return fmt.Sprintf("%.1f %s", count, unit)
		}
	}

	return "—"
}
