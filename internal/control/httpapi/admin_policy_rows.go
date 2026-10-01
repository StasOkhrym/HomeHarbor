package httpapi

import (
	"net/url"

	"github.com/sokhrym/go-tunnels/internal/control/devices"
)

type adminPolicyRow struct {
	ID          string
	Source      string
	Destination string
	Protocol    string
	From        string
	To          string
}

type adminPolicyRowModel struct {
	adminPolicyRow
	Devices    []devices.Device
	SourceName string
}

func (m adminPageModel) PolicyRow(row adminPolicyRow) adminPolicyRowModel {
	return adminPolicyRowModel{
		adminPolicyRow: row,
		Devices:        m.Devices.Items,
		SourceName:     m.DeviceName(row.Source),
	}
}

func (adminPageModel) BlankPolicyRow() adminPolicyRow { return adminPolicyRow{Protocol: "tcp"} }

// Preserve incomplete rows: parsing must not erase the input that needs to be
// corrected. This view conversion does not validate or authorize any rule.
func submittedPolicyRows(values url.Values) []adminPolicyRow {
	get := func(key string, index int) string {
		if index < len(values[key]) {
			return values[key][index]
		}
		return ""
	}
	rows := make([]adminPolicyRow, len(values["destination"]))
	for index := range rows {
		rows[index] = adminPolicyRow{
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
