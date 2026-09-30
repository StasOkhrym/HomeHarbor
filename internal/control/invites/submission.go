package invites

import "bytes"

// SameSubmission ignores server timestamps/status while comparing every byte
// of submitted authority. Retries can never replace another pending identity.
func SameSubmission(a, b Record) bool {
	return a.InviteID == b.InviteID && a.ProfileID == b.ProfileID && a.DeviceID == b.DeviceID &&
		bytes.Equal(a.DevicePublic, b.DevicePublic) && bytes.Equal(a.WireGuardPublicKey, b.WireGuardPublicKey) &&
		a.Permit.Version == b.Permit.Version && a.Permit.KeyID == b.Permit.KeyID && bytes.Equal(a.Permit.Payload, b.Permit.Payload) && bytes.Equal(a.Permit.Signature, b.Permit.Signature) &&
		a.Proof.Version == b.Proof.Version && a.Proof.InviteID == b.Proof.InviteID && a.Proof.DeviceID == b.Proof.DeviceID &&
		bytes.Equal(a.Proof.DevicePublicKey, b.Proof.DevicePublicKey) && bytes.Equal(a.Proof.WireGuardPublicKey, b.Proof.WireGuardPublicKey) && bytes.Equal(a.Proof.CodeDigest, b.Proof.CodeDigest) && bytes.Equal(a.Proof.Signature, b.Proof.Signature) && bytes.Equal(a.Proof.DeviceSignature, b.Proof.DeviceSignature)
}
