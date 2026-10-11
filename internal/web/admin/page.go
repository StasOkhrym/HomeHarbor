package admin

import (
	"context"
	"net/url"
	"strconv"

	"github.com/StasOkhrym/homeharbor/internal/acl"
	"github.com/StasOkhrym/homeharbor/internal/control/devices"
	"github.com/StasOkhrym/homeharbor/internal/control/invites"
	"github.com/StasOkhrym/homeharbor/internal/control/profiles"
	"github.com/StasOkhrym/homeharbor/internal/control/routes"
	"github.com/StasOkhrym/homeharbor/internal/control/services"
	"github.com/StasOkhrym/homeharbor/internal/snapshot"
)

// A failed read is not an empty collection. Templates display availability
// separately so an outage never looks like an unconfigured network.
type Collection[T any] struct {
	Items   []T
	Ready   bool
	Enabled bool
	Error   string
}

func (c Collection[T]) Count() string {
	if !c.Ready {
		return "—"
	}

	return strconv.Itoa(len(c.Items))
}

func LoadCollection[T any](
	ctx context.Context,
	label string,
	read func(context.Context) ([]T, error),
) Collection[T] {
	result := Collection[T]{Enabled: read != nil}
	if read == nil {
		result.Error = label + " is not configured"
		return result
	}

	items, err := read(ctx)
	if err != nil {
		result.Error = label + " could not be loaded"
		return result
	}

	result.Items, result.Ready = items, true

	return result
}

// Page is the typed presentation contract shared by full pages and fragments.
// The admin handler loads it; this package owns template-facing state.
type Page struct {
	Page          string
	Title         string
	Description   string
	CSRF          string
	Notice        string
	Error         string
	Values        url.Values
	FieldErrors   map[string]string
	Devices       Collection[devices.Device]
	Services      Collection[services.Service]
	Profiles      Collection[profiles.AccessProfile]
	Routes        Collection[routes.Advertisement]
	Activity      Activity
	Device        *devices.Device
	Policy        acl.Snapshot
	PolicyReady   bool
	PolicyJSON    string
	PolicyError   string
	Signed        *snapshot.NetworkSnapshot
	SignedState   string
	Readiness     string
	PendingRoutes string
	Invite        *Invite
	InviteError   string
	InvitesReady  bool
	Preview       *PolicyPreview
	RevokeProof   string
	PolicyRows    []PolicyRow
}

func NewPage(page, csrf, noticeCode string) Page {
	metadata := titles[page]
	return Page{
		Page:          page,
		Title:         metadata[0],
		Description:   metadata[1],
		CSRF:          csrf,
		Notice:        notices[noticeCode],
		Values:        url.Values{},
		FieldErrors:   map[string]string{},
		PendingRoutes: "—",
		SignedState:   "Signed configuration is not configured",
		Readiness:     "Readiness check is not configured",
	}
}

var titles = map[string][2]string{
	"overview": {"Overview", "Your network, without the guesswork."},
	"setup": {
		"Set up your network",
		"Follow the steps without losing access to the rest of the panel.",
	},
	"devices": {
		"Devices",
		"Manage registration and authentication. Tunnel connectivity is reported separately.",
	},
	"services": {"Services", "A simple catalog of your private applications."},
	"access": {
		"Access",
		"Manage profiles and default-deny rules. Saved settings are not signed access grants.",
	},
	"network": {"Network", "Review LAN routes and split DNS settings before approving them."},
	"invites": {
		"Invites",
		"Signed invites use your trusted companion. Legacy tokens are a separate mechanism.",
	},
	"activity": {"Activity", "Recent audit events from the control plane."},
	"security": {
		"Security",
		"Your passkey, recovery codes and network signing key have separate roles.",
	},
}

var notices = map[string]string{
	"service-created": "Service saved to the catalog. This does not grant network access.",
	"profile-created": "Access profile saved. Signed network configuration is a separate step.",
	"route-created":   "Route saved and awaiting approval.",
	"route-approved":  "Route approved in control. Gateway application is not confirmed.",
	"route-rejected":  "Route rejected in control. Existing signed grants are unchanged.",
	"policy-updated":  "Policy saved. This is not a signed network update.",
	"device-revoked":  "Credentials revoked. Use your trusted companion to remove the signed access grant.",
}

// Invite contains status metadata only; signed permits and proofs never enter
// the admin template.
type Invite struct {
	ID        string
	ProfileID string
	DeviceID  string
	Status    invites.Status
}

type PolicyPreview struct {
	Before    string
	After     string
	RulesJSON string
	Revision  uint64
	Proof     string
	Changes   []PolicyChange
}

type PolicyChange struct {
	Kind   string
	Before *acl.Rule
	After  *acl.Rule
}

func PolicyChanges(before, after []acl.Rule) []PolicyChange {
	old := make(map[string]acl.Rule, len(before))
	for _, rule := range before {
		old[rule.ID] = rule
	}

	var changes []PolicyChange
	for _, rule := range after {
		previous, exists := old[rule.ID]
		if !exists {
			changes = append(changes, PolicyChange{Kind: "Added", After: &rule})
		} else if previous != rule {
			changes = append(
				changes,
				PolicyChange{Kind: "Modified", Before: &previous, After: &rule},
			)
		}

		delete(old, rule.ID)
	}

	// Keep removals in stored order rather than random map iteration.
	for _, rule := range before {
		if _, exists := old[rule.ID]; exists {
			changes = append(changes, PolicyChange{Kind: "Removed", Before: &rule})
		}
	}

	return changes
}

type PolicyRow struct {
	ID          string
	Source      string
	Destination string
	Protocol    string
	From        string
	To          string
}

type PolicyRowModel struct {
	PolicyRow
	Devices    []devices.Device
	SourceName string
}

type Field struct {
	Name     string
	Label    string
	Type     string
	Value    string
	Error    string
	Required bool
}

func (m Page) Value(key string) string { return m.Values.Get(key) }

func (m Page) DeviceName(id string) string {
	for _, item := range m.Devices.Items {
		if item.ID == id {
			return item.Name
		}
	}

	return "Unavailable device"
}

func (m Page) ServiceName(id string) string {
	for _, item := range m.Services.Items {
		if item.ID == id {
			return item.Name
		}
	}

	return "Unavailable service"
}

func (m Page) Selected(key, value string) bool {
	for _, item := range m.Values[key] {
		if item == value {
			return true
		}
	}

	return false
}

func (m Page) Field(name, label, kind string, required bool) Field {
	return Field{
		Name:     name,
		Label:    label,
		Type:     kind,
		Required: required,
		Value:    m.Value(name),
		Error:    m.FieldErrors[name],
	}
}

func (m Page) PolicyRow(row PolicyRow) PolicyRowModel {
	return PolicyRowModel{
		PolicyRow:  row,
		Devices:    m.Devices.Items,
		SourceName: m.DeviceName(row.Source),
	}
}

func (Page) BlankPolicyRow() PolicyRow { return PolicyRow{Protocol: "tcp"} }

// Preserve incomplete rows so validation can show the exact input to correct.
func SubmittedPolicyRows(values url.Values) []PolicyRow {
	get := func(key string, index int) string {
		if index < len(values[key]) {
			return values[key][index]
		}

		return ""
	}
	rows := make([]PolicyRow, len(values["destination"]))
	for index := range rows {
		rows[index] = PolicyRow{
			ID:          get("rule_id", index),
			Source:      get("source_device_id", index),
			Destination: get("destination", index),
			Protocol:    get("protocol", index),
			From:        get("port_from", index),
			To:          get("port_to", index),
		}
	}

	return rows
}
