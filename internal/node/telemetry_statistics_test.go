package node

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/StasOkhrym/homeharbor/internal/tunnel"
)

func TestWireGuardStatisticsReadsOnlyBoundedPublicFields(t *testing.T) {
	identity, err := tunnel.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}

	values := map[string]string{
		"transfer":          identity.PublicKey + "\t10\t20\n",
		"latest-handshakes": identity.PublicKey + "\t123\n",
		"endpoints":         identity.PublicKey + "\t127.0.0.1:51820\n",
	}
	var fields []string

	reader, err := NewWireGuardStatistics(
		"wg-home",
		func(_ context.Context, name, field string) ([]byte, error) {
			if name != "wg-home" {
				t.Fatalf("wrong interface: %s", name)
			}

			text, ok := values[field]
			if !ok {
				t.Fatalf("nonpublic query requested: %s", field)
			}

			fields = append(fields, field)

			return []byte(text), nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	stats, err := reader.Read(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	got := stats[identity.PublicKey]

	if len(fields) != 3 || len(stats) != 1 || got.RXBytes != 10 || got.TXBytes != 20 ||
		got.LastHandshakeUnix != 123 ||
		got.Endpoint != "127.0.0.1:51820" {
		t.Fatalf("invalid public stats: fields=%v stats=%+v", fields, stats)
	}
}

func TestWireGuardStatisticsRejectsRawDumpAndSecretErrors(t *testing.T) {
	identity, err := tunnel.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}

	for _, data := range []string{
		identity.PrivateKey + "\t" + identity.PublicKey + "\t51820\t0\n",
		identity.PublicKey + "\t-1\t20\n",
		identity.PublicKey + "\t10\t20\n" + identity.PublicKey + "\t10\t20\n",
		strings.Repeat("SECRET", 20000),
	} {
		reader, err := NewWireGuardStatistics(
			"wg-home",
			func(context.Context, string, string) ([]byte, error) { return []byte(data), nil },
		)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := reader.Read(
			t.Context(),
		); err == nil || strings.Contains(err.Error(), identity.PrivateKey) ||
			strings.Contains(err.Error(), "SECRET") {
			t.Fatalf("raw/unsafe statistic accepted or leaked: %v", err)
		}
	}

	reader, err := NewWireGuardStatistics(
		"wg-home",
		func(context.Context, string, string) ([]byte, error) { return nil, errors.New("SECRET_COMMAND_ERROR") },
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := reader.Read(t.Context()); err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("command error leaked: %v", err)
	}

	if _, err := NewWireGuardStatistics("../../foreign", nil); err == nil {
		t.Fatal("unsafe interface selector accepted")
	}
}
