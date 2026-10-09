package healthcheck

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/cli/host"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(
	request *http.Request,
) (*http.Response, error) {
	return f(request)
}

func TestHealthcheckPreservesTwoSecondContextDeadline(t *testing.T) {
	client := &http.Client{
		Transport: transportFunc(func(request *http.Request) (*http.Response, error) {
			deadline, ok := request.Context().Deadline()

			if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 2*time.Second {
				t.Fatalf("request deadline = %v, present = %v", deadline, ok)
			}

			return &http.Response{
				StatusCode: http.StatusNoContent,
				Body:       io.NopCloser(bytes.NewReader(nil)),
			}, nil
		}),
	}
	var out, errOut bytes.Buffer

	if code := host.Execute(
		context.Background(),
		[]string{"http://example.test/healthz"},
		&out,
		&errOut,
		newCommand(client),
	); code != 0 {
		t.Fatalf("healthcheck exit = %d, stderr=%q", code, errOut.String())
	}
}

func TestHealthcheckHelpAndVersionDoNotProbe(t *testing.T) {
	called := false
	client := &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, errors.New("unexpected probe")
	})}
	for _, arg := range []string{"--help", "--version"} {
		var out, errOut bytes.Buffer

		if code := host.Execute(
			context.Background(),
			[]string{arg},
			&out,
			&errOut,
			newCommand(client),
		); code != 0 ||
			called {
			t.Fatalf("%s: exit=%d probed=%v stderr=%q", arg, code, called, errOut.String())
		}
	}
}

func TestHealthcheckCanceledOrUnhealthyIsFailure(t *testing.T) {
	for _, tc := range []struct {
		name   string
		client *http.Client
		ctx    context.Context
		want   int
	}{
		{name: "status", client: &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusServiceUnavailable, Status: "503 Service Unavailable", Body: io.NopCloser(bytes.NewReader(nil))}, nil
		})}, ctx: context.Background(), want: 1},
		{name: "canceled", client: &http.Client{Transport: transportFunc(func(req *http.Request) (*http.Response, error) {
			return nil, req.Context().Err()
		})}, ctx: canceledContext(), want: 130},
		{name: "network", client: &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("offline")
		})}, ctx: context.Background(), want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer

			if code := host.Execute(
				tc.ctx,
				[]string{"http://example.test/healthz"},
				&out,
				&errOut,
				newCommand(tc.client),
			); code != tc.want {
				t.Fatalf("exit = %d want %d, stderr=%q", code, tc.want, errOut.String())
			}
		})
	}
}

func canceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())

	cancel()
	return ctx
}
