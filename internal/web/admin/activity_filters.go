package admin

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/StasOkhrym/homeharbor/internal/control/audit"
)

type ActivityOption struct {
	Value string
	Label string
}

func activityFilters(view *Activity, values url.Values, query audit.Query) {
	view.Limit, view.BeforeID, view.Action, view.TargetID = query.Limit, query.BeforeID, query.Action, query.TargetID
	view.Category, view.Outcome, view.ActorID, view.DeviceID = query.Category, query.Outcome, query.ActorID, query.DeviceID
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
