package relay

import "testing"

// FuzzDecodePacket exercises the length-prefixed relay parser with arbitrary
// bytes. The parser is exposed to unauthenticated network input and must never
// panic or allocate based on an unchecked wire length.
func FuzzDecodePacket(f *testing.F) {
	f.Add([]byte{1, 's', 1, 'a', 1, 'd', 'p'})
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = DecodePacket(data)
	})
}

// FuzzDecodeUDPPairDatagram checks the UDP ingress envelope independently of
// ticket verification, ensuring malformed headers cannot reach session state.
func FuzzDecodeUDPPairDatagram(f *testing.F) {
	f.Add([]byte("GTUP\x01\x01\x00\x01tdata"))
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = DecodeUDPPairDatagram(data)
	})
}
