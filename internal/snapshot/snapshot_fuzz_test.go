package snapshot

import "testing"

// FuzzDecodeSnapshot keeps CBOR received from control or disk within the
// canonical snapshot decoder's error path. Nodes must reject malformed state,
// never panic while trying to recover from it.
func FuzzDecodeSnapshot(f *testing.F) {
	f.Add([]byte{0xa0})
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, payload []byte) {
		_, _ = Decode(Envelope{Version: SchemaVersion, Payload: payload})
	})
}
