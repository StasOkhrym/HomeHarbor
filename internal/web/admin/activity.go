// Package admin owns browser-facing control read models and presentation rules.
package admin

import (
	"context"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/audit"
)

type ActivityReader interface {
	ListRecords(context.Context, audit.Query) ([]audit.Record, error)
}

// Activity is one bounded, newest-first browser view. OlderID is an exclusive
// history cursor; live refresh always re-queries the recent committed window.
type Activity struct {
	Records         []audit.Record
	Ready           bool
	Error           string
	Limit           int
	Action          string
	TargetID        string
	BeforeID        int64
	OlderID         int64
	Category        string
	Outcome         string
	Period          string
	ActorID         string
	DeviceID        string
	ActionOptions   []audit.ActionOption
	CategoryOptions []ActivityOption
	OutcomeOptions  []ActivityOption
	PeriodOptions   []ActivityOption
	ActorOptions    []ActivityOption
	DeviceOptions   []ActivityOption
}

func LoadActivity(
	ctx context.Context,
	reader ActivityReader,
	values url.Values,
) (Activity, int) {
	view, status := loadActivity(ctx, reader, values, time.Now())
	if status != http.StatusOK {
		return view, status
	}

	facets := audit.Facets{}
	if source, ok := reader.(interface {
		ListFacets(context.Context) (audit.Facets, error)
	}); ok {
		var err error

		facets, err = source.ListFacets(ctx)
		if err != nil {
			view.Ready = false
			view.Error = "Activity filters could not be loaded"

			return view, http.StatusServiceUnavailable
		}
	}

	view.ActorOptions = identityOptions(facets.Actors, view.ActorID, "All administrators")
	view.DeviceOptions = identityOptions(facets.Devices, view.DeviceID, "All devices")

	return view, status
}

func loadActivity(
	ctx context.Context,
	reader ActivityReader,
	values url.Values,
	now time.Time,
) (Activity, int) {
	view := Activity{}

	query, err := audit.ParseQuery(values, now, audit.DefaultQueryLimit)
	if err != nil {
		view.Error = err.Error()
		return view, http.StatusBadRequest
	}

	activityFilters(&view, values, query)
	if reader == nil {
		view.Error = "Activity is not configured"
		return view, http.StatusServiceUnavailable
	}

	records, err := reader.ListRecords(ctx, query)
	if err != nil {
		view.Error = "Activity could not be loaded"
		return view, http.StatusServiceUnavailable
	}

	for i := range records {
		records[i].Event = audit.PublicEvent(records[i].Event)
	}

	view.Records, view.Ready = records, true
	if len(records) == view.Limit && len(records) > 0 {
		view.OlderID = records[len(records)-1].RecordID
	}

	return view, http.StatusOK
}

func ActionLabel(action string) string { return audit.ActionLabel(action) }

func Actor(event audit.Event) string {
	if event.ActorType == "" || event.ActorType == "unknown" || event.ActorID == "" {
		return "Unknown actor"
	}

	if name, ok := audit.PublicEvent(event).Metadata["actor_name"].(string); ok {
		return name
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
