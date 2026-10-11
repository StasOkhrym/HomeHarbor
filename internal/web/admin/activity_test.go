package admin

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

type fragmentActivityReader struct {
	calls int
	query audit.Query
}

func (reader *fragmentActivityReader) ListRecords(
	_ context.Context,
	query audit.Query,
) ([]audit.Record, error) {
	reader.calls++
	reader.query = query

	return []audit.Record{{RecordID: 7, Event: audit.Event{Action: "admin.login"}}}, nil
}

func TestActivityFragmentRendersOnlyBoundedUncachedRows(t *testing.T) {
	reader := &fragmentActivityReader{}

	handler := ActivityFragment(reader, slog.New(slog.NewTextHandler(io.Discard, nil)))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, httptest.NewRequest(
		http.MethodGet, "/admin/activity/fragment?limit=999", nil,
	))

	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" ||
		reader.query.Limit != audit.MaxQueryLimit || reader.calls != 1 ||
		!strings.Contains(response.Body.String(), `data-record-id="7"`) ||
		strings.Contains(response.Body.String(), "<html") {
		t.Fatalf("fragment status=%d query=%+v calls=%d body=%s",
			response.Code, reader.query, reader.calls, response.Body.String())
	}

	response = httptest.NewRecorder()

	handler.ServeHTTP(response, httptest.NewRequest(
		http.MethodGet, "/admin/activity/fragment?before_id=bad", nil,
	))

	if response.Code != http.StatusBadRequest || reader.calls != 1 ||
		response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("invalid cursor status=%d calls=%d cache=%q",
			response.Code, reader.calls, response.Header().Get("Cache-Control"))
	}
}
