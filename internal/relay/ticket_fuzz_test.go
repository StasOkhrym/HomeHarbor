package relay

import (
	"testing"
	"time"
)

// FuzzRelayTicketVerify exercises the current admission credential parser.
func FuzzRelayTicketVerify(f *testing.F) {
	issuer := TicketIssuer{Key: []byte("01234567890123456789012345678901")}

	valid, err := issuer.IssueForPeer("session", "client", "gateway", time.Minute)
	if err != nil {
		f.Fatal(err)
	}

	f.Add(valid)
	f.Add("")
	f.Add(valid + ".tampered")
	f.Fuzz(func(_ *testing.T, ticket string) {
		_, _ = issuer.Verify(ticket)
	})
}
