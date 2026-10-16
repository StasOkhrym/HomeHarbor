package audit

import (
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ParseQuery is the common browser/API filter contract. Period bounds are UTC
// and half-open; a supplied invalid facet never silently broadens the result.
func ParseQuery(values url.Values, now time.Time, defaultLimit int) (Query, error) {
	q := Query{
		Limit:    defaultLimit,
		Action:   strings.TrimSpace(values.Get("action")),
		TargetID: strings.TrimSpace(values.Get("target_id")),
		Category: strings.TrimSpace(values.Get("category")),
		Outcome:  strings.TrimSpace(values.Get("outcome")),
		ActorID:  strings.TrimSpace(values.Get("actor_id")),
		DeviceID: strings.TrimSpace(values.Get("device_id")),
	}
	if raw := values.Get("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 1 {
			return Query{}, errors.New("choose a positive number of audit events")
		}

		q.Limit = min(limit, MaxQueryLimit)
	}

	if raw := values.Get("before_id"); raw != "" {
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || id < 1 {
			return Query{}, errors.New("choose a valid activity cursor")
		}

		q.BeforeID = id
	}

	var duration time.Duration
	switch values.Get("period") {
	case "", "all":
	case "1h":
		duration = time.Hour
	case "24h":
		duration = 24 * time.Hour
	case "7d":
		duration = 7 * 24 * time.Hour
	case "30d":
		duration = 30 * 24 * time.Hour
	default:
		return Query{}, errors.New("choose a valid activity period")
	}

	if duration > 0 {
		q.Since = now.UTC().Add(-duration)
		q.Until = now.UTC()
	}

	return q, q.Validate()
}
