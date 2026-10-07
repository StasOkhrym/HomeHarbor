// Package controlclient owns bounded HTTP transport to the control API.
// Callers retain signing, authorization, and credential-state decisions.
package controlclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const MaxJSONBytes = 1 << 20

// StatusError exposes an HTTP status without reflecting an untrusted body or credential.
type StatusError struct {
	Operation  string
	StatusCode int
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("control %s: HTTP status %d", e.Operation, e.StatusCode)
}

type Client struct {
	base string
	http *http.Client
}

// New accepts only an origin. A nil HTTP client uses the standard transport
// with a finite deadline; a supplied client must already have a positive timeout.
// Redirects are never followed, including on GET and credential-free requests.
func New(baseURL *url.URL, transport *http.Client) (*Client, error) {
	if baseURL == nil || baseURL.Host == "" || baseURL.User != nil ||
		baseURL.Path != "" || baseURL.RawPath != "" || baseURL.RawQuery != "" ||
		baseURL.Fragment != "" || baseURL.Opaque != "" {
		return nil, errors.New("control endpoint must be an origin")
	}

	localHTTP := baseURL.Scheme == "http" &&
		(baseURL.Hostname() == "localhost" || baseURL.Hostname() == "127.0.0.1" || baseURL.Hostname() == "::1")
	if baseURL.Scheme != "https" && !localHTTP {
		return nil, errors.New("control endpoint must use HTTPS or local HTTP")
	}

	if transport == nil {
		transport = &http.Client{Timeout: 15 * time.Second}
	} else if transport.Timeout <= 0 {
		return nil, errors.New("control HTTP client requires a positive timeout")
	}

	copyClient := *transport
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	return &Client{base: baseURL.String(), http: &copyClient}, nil
}

// ForEndpoint adapts existing call sites whose supplied HTTP client may omit
// a timeout. Their transport and TLS roots are retained, with a finite bound.
func ForEndpoint(raw string, transport *http.Client) (*Client, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("invalid control endpoint")
	}

	if transport != nil && transport.Timeout <= 0 {
		bounded := *transport
		bounded.Timeout = 15 * time.Second
		transport = &bounded
	}

	return New(parsed, transport)
}

// request sends one API request without retries or redirects.
func (c *Client) request(
	ctx context.Context,
	method, path, credential string,
	headers http.Header,
	body, result any,
	expected int,
	strict bool,
) error {
	if c == nil || ctx == nil || !strings.HasPrefix(path, "/api/v1/") ||
		strings.Contains(path, "#") || strings.HasPrefix(path, "//") {
		return errors.New("invalid control request")
	}
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode control request: %w", err)
		}
		if len(encoded) > MaxJSONBytes {
			return errors.New("control request exceeds JSON limit")
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return errors.New("invalid control request URL")
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if credential != "" {
		request.Header.Set("Authorization", "Bearer "+credential)
	}
	for name, values := range headers {
		if strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "Host") {
			return errors.New("reserved control request header")
		}
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
	response, err := c.http.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("control request transport failed")
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != expected {
		return &StatusError{
			Operation:  method + " " + pathOperation(path),
			StatusCode: response.StatusCode,
		}
	}
	limit := MaxJSONBytes
	if strict {
		limit = 64 << 10 // Preserve the activation/recovery response bound.
	}
	if strings.HasSuffix(path, "/approval") {
		limit = 16 << 10 // Preserve the public approval response bound.
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, int64(limit+1)))
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("control response read failed")
	}
	if len(data) > limit {
		return errors.New("control response exceeds JSON limit")
	}
	if result == nil {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if strict {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(result); err != nil {
		return errors.New("invalid control JSON response")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("invalid trailing control JSON")
	}
	return nil
}

func pathOperation(path string) string {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}

	// Do not disclose invite IDs or arbitrary path segments in error strings.
	if strings.HasPrefix(path, "/api/v1/invites/") {
		return "/api/v1/invites/{id}"
	}

	return path
}
