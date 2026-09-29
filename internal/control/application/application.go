// Package application contains the control-plane composition root. It owns
// wiring only; cross-module business workflows belong in explicit facades.
package application

import (
	"github.com/sokhrym/go-tunnels/internal/control/audit"
	"github.com/sokhrym/go-tunnels/internal/control/devices"
	"github.com/sokhrym/go-tunnels/internal/control/identity"
	controlnetwork "github.com/sokhrym/go-tunnels/internal/control/network"
	"github.com/sokhrym/go-tunnels/internal/control/policy"
)

type Application struct {
	Devices  *devices.Service
	Identity *identity.Service
	Passkeys *identity.PasskeyService
	Network  *controlnetwork.Service
	Policy   *policy.Service
	Audit    *audit.PostgresSink
}
