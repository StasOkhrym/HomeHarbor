package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/StasOkhrym/homeharbor/internal/acl"
	"github.com/StasOkhrym/homeharbor/internal/control/invites"
	controlsnapshots "github.com/StasOkhrym/homeharbor/internal/control/snapshots"
	"github.com/StasOkhrym/homeharbor/internal/snapshot"
)

type PolicyReader interface {
	Latest(context.Context) (acl.Snapshot, error)
}

type SnapshotReader interface {
	Latest(context.Context) (snapshot.Envelope, error)
}

type InviteReader interface {
	Get(context.Context, string) (invites.Record, error)
}

// LoadPolicy keeps storage errors separate from an empty deny-all ruleset.
func LoadPolicy(ctx context.Context, reader PolicyReader, model *Page) {
	model.PolicyError = "Policy is not configured"
	if reader == nil {
		return
	}

	value, err := reader.Latest(ctx)
	if err != nil {
		model.PolicyError = "Policy could not be loaded"
		return
	}

	if value.Rules == nil {
		value.Rules = []acl.Rule{}
	}

	encoded, err := json.MarshalIndent(value.Rules, "", "  ")
	if err != nil {
		model.PolicyError = "Policy could not be displayed"
		return
	}

	model.Policy, model.PolicyJSON, model.PolicyReady = value, string(encoded), true
	model.PolicyError = ""
	model.Values.Set("rules", model.PolicyJSON)
	for _, rule := range value.Rules {
		model.PolicyRows = append(model.PolicyRows, PolicyRow{
			ID:          rule.ID,
			Source:      rule.SourceDeviceID,
			Destination: rule.Destination.String(),
			Protocol:    string(rule.Protocol),
			From:        strconv.Itoa(int(rule.PortFrom)),
			To:          strconv.Itoa(int(rule.PortTo)),
		})
	}

	model.PolicyRows = append(model.PolicyRows, PolicyRow{Protocol: "tcp"})
}

func LoadSignedState(ctx context.Context, reader SnapshotReader, model *Page) {
	if reader == nil {
		return
	}

	envelope, err := reader.Latest(ctx)
	if errors.Is(err, controlsnapshots.ErrSnapshotUnavailable) {
		model.SignedState = "No signed configuration has been published"
		return
	}
	if err != nil {
		model.SignedState = "Signed configuration could not be loaded"
		return
	}

	value, err := snapshot.Decode(envelope)
	if err != nil {
		model.SignedState = "Signed configuration could not be displayed"
		return
	}

	model.Signed = &value
	model.SignedState = fmt.Sprintf("Signed revision %d · Published", value.Revision)
}

func LoadInvite(ctx context.Context, rawID string, reader InviteReader, model *Page) {
	id := strings.TrimSpace(rawID)
	model.Values.Set("invite_id", id)
	if id == "" || reader == nil {
		return
	}
	if len(id) > 128 {
		model.InviteError = "Enter a valid invite ID, not an invite link or code."
		return
	}

	record, err := reader.Get(ctx, id)
	if errors.Is(err, invites.ErrInviteNotFound) {
		model.InviteError = "Invite not found. It may not have received a device proof yet."
	} else if err != nil {
		model.InviteError = "Invite status could not be loaded. Try again shortly."
	} else {
		model.Invite = &Invite{
			ID:        record.InviteID,
			ProfileID: record.ProfileID,
			DeviceID:  record.DeviceID,
			Status:    record.Status,
		}
	}
}
