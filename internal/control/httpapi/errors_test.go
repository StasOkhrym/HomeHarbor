package httpapi

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteServiceErrorDoesNotExposeInternalDetails(t *testing.T) {
	recorder := httptest.NewRecorder()

	writeServiceError(
		recorder,
		errors.New("pq: password authentication failed for user homeharbor"),
	)

	if recorder.Code != 400 {
		t.Fatalf("status=%d, want 400", recorder.Code)
	}

	body := recorder.Body.String()

	if strings.Contains(body, "pq:") || strings.Contains(body, "password authentication") {
		t.Fatalf("internal error leaked in response: %s", body)
	}
	if !strings.Contains(body, `"code":"invalid_request"`) {
		t.Fatalf("stable public error code missing: %s", body)
	}
}
