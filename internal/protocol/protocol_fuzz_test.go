package protocol

import (
	"encoding/json"
	"testing"
)

// FuzzCandidateUpdateJSON keeps the untrusted coordination payload parser
// bounded. Validation is intentionally separate from JSON decoding so a
// syntactically valid but unsafe candidate update is still rejected.
func FuzzCandidateUpdateJSON(f *testing.F) {
	f.Add([]byte(`{"destination_device_id":"gateway","candidates":[]}`))
	f.Add([]byte(`{"destination_device_id":"gateway","candidates":[{"type":"host","address":"192.0.2.1:51820","priority":1}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var update CandidateUpdate
		if err := json.Unmarshal(data, &update); err == nil {
			_ = update.Validate()
		}
	})
}
