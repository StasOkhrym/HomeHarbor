package relay

import (
	"testing"
	"time"
)

func TestPeerTicketsAreUniqueWithinOneSecond(t *testing.T) {
	i := TicketIssuer{
		Key: []byte("01234567890123456789012345678901"),
		Now: func() time.Time { return time.Unix(1800000000, 0) },
	}

	a, err := i.IssueForPeer("s", "a", "b", time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	b, err := i.IssueForPeer("s", "a", "b", time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	if a == b {
		t.Fatal("fresh peer ticket replayed the previous admission credential")
	}
}
