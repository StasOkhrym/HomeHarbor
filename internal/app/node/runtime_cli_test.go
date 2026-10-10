package node

import (
	"context"
	"strings"
	"testing"

	"github.com/StasOkhrym/homeharbor/internal/node"
	"github.com/StasOkhrym/homeharbor/internal/platform/config"
)

func TestRelayConfigurationErrorsNameCobraLongFlags(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  config.Node
		want []string
	}{
		{name: "missing session", want: []string{"--relay-session", "--relay-destination"}},
		{
			name: "ticket without relay endpoint",
			cfg: config.Node{Relay: config.NodeRelay{
				SessionID: "session", DestinationDevice: "peer", Ticket: "ticket",
			}},
			want: []string{"--relay", "--relay-ticket"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := prepareRelay(context.Background(), tc.cfg, node.State{}, nil, nil, nil, nil)
			if err == nil {
				t.Fatal("expected relay configuration error")
			}
			for _, flag := range tc.want {
				if !strings.Contains(err.Error(), flag) {
					t.Fatalf("error %q omits %s", err, flag)
				}
			}
		})
	}
}
