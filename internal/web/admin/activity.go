// Package admin owns browser-facing control read models and presentation rules.
package admin

import (
	"context"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/StasOkhrym/homeharbor/internal/control/audit"
)

type ActivityReader interface {
	ListRecords(context.Context, audit.Query) ([]audit.Record, error)
}

// Activity is one bounded, newest-first browser view. OlderID is an exclusive
// history cursor; live refresh always re-queries the recent committed window.
type Activity struct {
	Records  []audit.Record
	Ready    bool
	Error    string
	Limit    int
	Action   string
	TargetID string
	BeforeID int64
	OlderID  int64
}

func LoadActivity(
	ctx context.Context,
	reader ActivityReader,
	values url.Values,
) (Activity, int) {
	view := Activity{Limit: audit.DefaultQueryLimit}
	if raw := values.Get("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 1 {
			view.Error = "Choose a positive number of audit events."
			return view, http.StatusBadRequest
		}
		view.Limit = min(limit, audit.MaxQueryLimit)
	}
	view.Action = strings.TrimSpace(values.Get("action"))
	view.TargetID = strings.TrimSpace(values.Get("target_id"))
	if len(view.Action) > 128 || len(view.TargetID) > 128 {
		view.Error = "Activity filters are too long."
		return view, http.StatusBadRequest
	}
	if raw := values.Get("before_id"); raw != "" {
		beforeID, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || beforeID < 1 {
			view.Error = "Choose a valid activity cursor."
			return view, http.StatusBadRequest
		}
		view.BeforeID = beforeID
	}
	if reader == nil {
		view.Error = "Activity is not configured"
		return view, http.StatusServiceUnavailable
	}
	records, err := reader.ListRecords(ctx, audit.Query{
		Limit: view.Limit, BeforeID: view.BeforeID,
		Action: view.Action, TargetID: view.TargetID,
	})
	if err != nil {
		view.Error = "Activity could not be loaded"
		return view, http.StatusServiceUnavailable
	}
	view.Records, view.Ready = records, true
	if len(records) == view.Limit && len(records) > 0 {
		view.OlderID = records[len(records)-1].RecordID
	}
	return view, http.StatusOK
}

var actionLabels = map[string]string{
	"device.enrolled":             "Device registered",
	"device.revoked":              "Device credentials revoked",
	"device.credential_rotated":   "Device credential rotated",
	"device.credential_recovered": "Device credential recovered",
	"device.credential_claimed":   "Device credential claimed",
	"invite.approved":             "Invite approved",
	"admin.bootstrap":             "First administrator passkey setup",
	"admin.login":                 "Passkey sign-in",
	"admin.recovery":              "Recovery sign-in",
	"admin.logout":                "Administrator sign-out",
	"admin.auth":                  "Administrator authentication check",
}

func ActionLabel(action string) string {
	if label, ok := actionLabels[action]; ok {
		return label
	}
	return "Other activity"
}

func Actor(event audit.Event) string {
	if event.ActorType == "" || event.ActorType == "unknown" || event.ActorID == "" {
		return "Unknown actor"
	}
	return event.ActorType + " / " + event.ActorID
}

// Missing outcome is unknown, never success. Arbitrary metadata is not shown.
func Outcome(event audit.Event) string {
	success, ok := event.Metadata["success"].(bool)
	if ok {
		if success {
			return "Succeeded"
		}

		return "Failed"
	}

	switch event.Metadata["outcome"] {
	case "success":
		return "Succeeded"
	case "failure":
		return "Failed"
	}

	return "Outcome unknown"
}

func Correlation(event audit.Event) string {
	correlation, _ := event.Metadata["correlation_id"].(string)
	return correlation
}

func Revision(event audit.Event) string {
	switch value := event.Metadata["aggregate_revision"].(type) {
	case int64:
		if value > 0 {
			return strconv.FormatInt(value, 10)
		}
	case float64:
		if value > 0 && value <= 1<<53 && math.Trunc(value) == value {
			return strconv.FormatInt(int64(value), 10)
		}
	}

	return ""
}
