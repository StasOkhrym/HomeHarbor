package admin

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/StasOkhrym/homeharbor/internal/control/audit"
)

type activityReaderStub struct{ err error }

func (reader activityReaderStub) ListRecords(context.Context, audit.Query) ([]audit.Record, error) {
	return nil, reader.err
}

func TestActivityKeepsUnavailableSeparateFromEmpty(t *testing.T) {
	unavailable, status := LoadActivity(
		t.Context(),
		activityReaderStub{err: errors.New("db down")},
		url.Values{},
	)

	if status != http.StatusServiceUnavailable || unavailable.Ready || unavailable.Error == "" ||
		len(unavailable.Records) != 0 {
		t.Fatalf("unavailable status=%d view=%+v", status, unavailable)
	}

	empty, status := LoadActivity(t.Context(), activityReaderStub{}, url.Values{})

	if status != http.StatusOK || !empty.Ready || empty.Error != "" || len(empty.Records) != 0 {
		t.Fatalf("empty status=%d view=%+v", status, empty)
	}
}
