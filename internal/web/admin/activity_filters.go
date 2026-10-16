package admin

import (
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/audit"
)

type ActivityOption struct {
	Value string
	Label string
}

func activityFilters(view *Activity, values url.Values, now time.Time) (audit.Query, error) {
	view.Category = strings.TrimSpace(values.Get("category"))
	view.Outcome = strings.TrimSpace(values.Get("outcome"))
	view.ActorID = strings.TrimSpace(values.Get("actor_id"))
	view.DeviceID = strings.TrimSpace(values.Get("device_id"))
	view.Period = values.Get("period")
	if view.Period == "" {
		view.Period = "all"
	}
	view.ActionOptions = audit.Actions()
	action := strings.TrimSpace(values.Get("action"))
	if action != "" && audit.ActionLabel(action) == "Other activity" {
		view.ActionOptions = append(
			view.ActionOptions,
			audit.ActionOption{Value: action, Label: "Other event · " + action},
		)
	}
	view.CategoryOptions = []ActivityOption{
		{"", "All categories"},
		{"security", "Sign-in & security"},
		{"devices", "Devices"},
		{"access", "Invites & access"},
		{"administrators", "Administrators"},
		{"system", "System"},
	}
	view.OutcomeOptions = []ActivityOption{
		{"", "All results"},
		{"success", "Succeeded"},
		{"failure", "Failed"},
		{"unknown", "Not recorded"},
	}
	view.PeriodOptions = []ActivityOption{
		{"all", "Any time"},
		{"1h", "Last hour"},
		{"24h", "Last 24 hours"},
		{"7d", "Last 7 days"},
		{"30d", "Last 30 days"},
	}
	query := audit.Query{
		Category: view.Category,
		Outcome:  view.Outcome,
		ActorID:  view.ActorID,
		DeviceID: view.DeviceID,
	}
	var duration time.Duration
	switch view.Period {
	case "all":
	case "1h":
		duration = time.Hour
	case "24h":
		duration = 24 * time.Hour
	case "7d":
		duration = 7 * 24 * time.Hour
	case "30d":
		duration = 30 * 24 * time.Hour
	default:
		return audit.Query{}, errors.New("choose a valid activity period")
	}
	if duration > 0 {
		query.Since = now.UTC().Add(-duration)
		query.Until = now.UTC()
	}
	return query, query.Validate()
}

func (a Activity) OlderURL() string {
	values := url.Values{
		"limit":     {strconv.Itoa(a.Limit)},
		"before_id": {strconv.FormatInt(a.OlderID, 10)},
	}
	for name, value := range map[string]string{"category": a.Category, "action": a.Action, "target_id": a.TargetID, "outcome": a.Outcome, "period": a.Period, "actor_id": a.ActorID, "device_id": a.DeviceID} {
		if value != "" {
			values.Set(name, value)
		}
	}

	return "/admin/activity?" + values.Encode()
}
