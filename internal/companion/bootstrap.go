package companion

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/StasOkhrym/homeharbor/internal/snapshot"
)

// SnapshotManifest is the operator-authored, TOML representation of the
// initial signed network state. It is intentionally local-only: the control
// plane never receives this source document or a root private key.
type SnapshotManifest struct {
	NetworkID string            `toml:"network_id"`
	Devices   []ManifestDevice  `toml:"devices"`
	Gateways  []ManifestGateway `toml:"gateways"`
	Routes    []ManifestRoute   `toml:"routes"`
	Services  []ManifestService `toml:"services"`
	Profiles  []ManifestProfile `toml:"profiles"`
	ACL       []ManifestACLRule `toml:"acl"`
}

type ManifestDevice struct {
	ID                 string `toml:"id"`
	Role               string `toml:"role"`
	IdentityPublicKey  string `toml:"identity_public_key"`
	WireGuardPublicKey string `toml:"wireguard_public_key"`
	OverlayAddress     string `toml:"overlay_address"`
}

type ManifestGateway struct {
	DeviceID string `toml:"device_id"`
	Name     string `toml:"name"`
}

type ManifestRoute struct {
	ID           string `toml:"id"`
	GatewayID    string `toml:"gateway_id"`
	Prefix       string `toml:"prefix"`
	DomainSuffix string `toml:"domain_suffix"`
	Resolver     string `toml:"resolver"`
}

type ManifestService struct {
	ID          string `toml:"id"`
	Name        string `toml:"name"`
	Kind        string `toml:"kind"`
	URL         string `toml:"url"`
	NativeURL   string `toml:"native_url"`
	HealthURL   string `toml:"health_url"`
	Description string `toml:"description"`
}

type ManifestProfile struct {
	ID         string   `toml:"id"`
	Name       string   `toml:"name"`
	DeviceIDs  []string `toml:"device_ids"`
	ServiceIDs []string `toml:"service_ids"`
	ACLRuleIDs []string `toml:"acl_rule_ids"`
}

type ManifestACLRule struct {
	ID             string `toml:"id"`
	SourceDeviceID string `toml:"source_device_id"`
	Destination    string `toml:"destination"`
	Protocol       string `toml:"protocol"`
	PortFrom       uint16 `toml:"port_from"`
	PortTo         uint16 `toml:"port_to"`
}

// LoadSnapshotManifest decodes an explicit first-network manifest. A separate
// manifest type keeps TOML naming stable without putting transport/config tags
// on the signed CBOR domain model.
func LoadSnapshotManifest(path string) (SnapshotManifest, error) {
	if strings.TrimSpace(path) == "" {
		return SnapshotManifest{}, errors.New("snapshot manifest path is required")
	}

	var manifest SnapshotManifest

	if _, err := toml.DecodeFile(path, &manifest); err != nil {
		return SnapshotManifest{}, fmt.Errorf("decode snapshot manifest: %w", err)
	}

	if strings.TrimSpace(manifest.NetworkID) == "" {
		return SnapshotManifest{}, errors.New("snapshot manifest network_id is required")
	}

	return manifest, nil
}

// SignInitialSnapshot creates only revision one. The control plane accepts it
// only when no signed head exists, so rerunning the command cannot overwrite
// an established network or silently reset its revision chain.
func (m SnapshotManifest) SignInitialSnapshot(
	privateKey ed25519.PrivateKey,
	keyID string,
) (snapshot.Envelope, error) {
	networkID := strings.TrimSpace(m.NetworkID)
	keyID = strings.TrimSpace(keyID)
	if len(privateKey) != ed25519.PrivateKeySize || keyID == "" {
		return snapshot.Envelope{}, errors.New("root key and key ID are required")
	}
	if networkID == "" {
		return snapshot.Envelope{}, errors.New("snapshot network ID is required")
	}
	if len(m.Gateways) == 0 {
		return snapshot.Envelope{}, errors.New("initial snapshot must declare at least one gateway")
	}

	value := snapshot.NetworkSnapshot{
		NetworkID: networkID,
		Revision:  1,
		Devices:   make([]snapshot.Device, 0, len(m.Devices)),
		Gateways:  make([]snapshot.Gateway, 0, len(m.Gateways)),
		Routes:    make([]snapshot.Route, 0, len(m.Routes)),
		Services:  make([]snapshot.Service, 0, len(m.Services)),
		Profiles:  make([]snapshot.AccessProfile, 0, len(m.Profiles)),
		ACL:       make([]snapshot.ACLRule, 0, len(m.ACL)),
	}
	for _, device := range m.Devices {
		value.Devices = append(
			value.Devices,
			snapshot.Device{
				ID:                 device.ID,
				Role:               device.Role,
				IdentityPublicKey:  device.IdentityPublicKey,
				WireGuardPublicKey: device.WireGuardPublicKey,
				OverlayAddress:     device.OverlayAddress,
			},
		)
	}

	for _, gateway := range m.Gateways {
		value.Gateways = append(
			value.Gateways,
			snapshot.Gateway{DeviceID: gateway.DeviceID, Name: gateway.Name},
		)
	}

	for _, route := range m.Routes {
		value.Routes = append(
			value.Routes,
			snapshot.Route{
				ID:           route.ID,
				GatewayID:    route.GatewayID,
				Prefix:       route.Prefix,
				DomainSuffix: route.DomainSuffix,
				Resolver:     route.Resolver,
			},
		)
	}

	for _, service := range m.Services {
		value.Services = append(
			value.Services,
			snapshot.Service{
				ID:          service.ID,
				Name:        service.Name,
				Kind:        service.Kind,
				URL:         service.URL,
				NativeURL:   service.NativeURL,
				HealthURL:   service.HealthURL,
				Description: service.Description,
			},
		)
	}

	for _, profile := range m.Profiles {
		value.Profiles = append(
			value.Profiles,
			snapshot.AccessProfile{
				ID:         profile.ID,
				Name:       profile.Name,
				DeviceIDs:  append([]string(nil), profile.DeviceIDs...),
				ServiceIDs: append([]string(nil), profile.ServiceIDs...),
				ACLRuleIDs: append([]string(nil), profile.ACLRuleIDs...),
			},
		)
	}

	for _, rule := range m.ACL {
		value.ACL = append(
			value.ACL,
			snapshot.ACLRule{
				ID:             rule.ID,
				SourceDeviceID: rule.SourceDeviceID,
				Destination:    rule.Destination,
				Protocol:       rule.Protocol,
				PortFrom:       rule.PortFrom,
				PortTo:         rule.PortTo,
			},
		)
	}

	return snapshot.Sign(value, privateKey, keyID)
}
