package path

import (
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/protocol"
)

func TestPathSelectorFallsBackAndRecovers(t *testing.T) {
	selector := NewPathSelector()

	if got := selector.Current(); got != protocol.PathRelay {
		t.Fatalf("initial path = %q", got)
	}

	selector.DirectHandshakeSucceeded()

	if got := selector.Current(); got != protocol.PathDirect {
		t.Fatalf("direct path = %q", got)
	}

	selector.DirectFailed()

	if got := selector.Current(); got != protocol.PathRelay {
		t.Fatalf("fallback path = %q", got)
	}
}

func TestPathSelectorNotifiesTransportWatchersOnChange(t *testing.T) {
	selector := NewPathSelector()

	changes := selector.Changes()

	selector.DirectHandshakeSucceeded()
	select {
	case <-changes:
	case <-time.After(time.Second):
		t.Fatal("direct path change was not published")
	}

	if got := selector.Current(); got != protocol.PathDirect {
		t.Fatalf("path=%q, want direct", got)
	}

	nextChanges := selector.Changes()

	selector.DirectFailed()
	select {
	case <-nextChanges:
	case <-time.After(time.Second):
		t.Fatal("relay fallback change was not published")
	}
}
