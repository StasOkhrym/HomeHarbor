package node

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/snapshot"
)

const (
	snapshotHistoryPageSize = 16
	maxSnapshotHistoryBytes = snapshotHistoryPageSize*(maxSnapshotEnvelopeBytes+1) + 2
)

func fetchSnapshotHistory(
	ctx context.Context,
	cfg CoordinationConfig,
	revision uint64,
	hash []byte,
) ([]snapshot.Envelope, error) {
	endpoint, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, err
	}

	switch endpoint.Scheme {
	case "ws":
		endpoint.Scheme = "http"
	case "wss":
		endpoint.Scheme = "https"
	default:
		return nil, errors.New("coordination requires ws or wss URL")
	}

	endpoint.Path, endpoint.RawPath, endpoint.Fragment = "/api/v1/coordination/snapshots", "", ""
	query := url.Values{
		"after_revision": {strconv.FormatUint(revision, 10)},
		"limit":          {strconv.Itoa(snapshotHistoryPageSize)},
	}
	if revision > 0 {
		query.Set("after_hash", base64.RawURLEncoding.EncodeToString(hash))
	}

	endpoint.RawQuery = query.Encode()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}

	if cfg.Leases != nil {
		lease, err := cfg.Leases.Current(ctx)
		if err != nil {
			return nil, err
		}
		if lease.DeviceID != cfg.DeviceID || !lease.ExpiresAt.After(time.Now()) {
			return nil, errors.New("invalid history credential lease")
		}

		operation, cancel := context.WithDeadline(ctx, lease.ExpiresAt)
		defer cancel()

		request = request.WithContext(operation)
		cfg.Credential = lease.Credential
	}

	request.Header.Set("Authorization", "Bearer "+cfg.Credential)
	// Reuse the explicitly provisioned CA from the coordination connection.
	// A redirect must not move a credential-bearing history request.
	transport := http.DefaultTransport
	if cfg.HTTPClient != nil && cfg.HTTPClient.Transport != nil {
		transport = cfg.HTTPClient.Transport
	}

	client := &http.Client{
		Transport:     transport,
		Timeout:       15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("snapshot history HTTP status %d", response.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(response.Body, maxSnapshotHistoryBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxSnapshotHistoryBytes {
		return nil, errors.New("snapshot history exceeds page body limit")
	}

	var page []snapshot.Envelope

	if err := json.Unmarshal(data, &page); err != nil {
		return nil, err
	}

	if len(page) > snapshotHistoryPageSize {
		return nil, errors.New("snapshot history exceeds page count limit")
	}

	for _, envelope := range page {
		encoded, err := json.Marshal(envelope)
		if err != nil || len(encoded) > maxSnapshotEnvelopeBytes {
			return nil, errors.New("snapshot history exceeds envelope limit")
		}
	}

	return page, nil
}

// A WS head is only a signed catch-up target. It never bypasses missing
// revisions, including on a fresh node that was absent from early topology.
func reconcileSnapshotHead(
	ctx context.Context,
	cfg CoordinationConfig,
	applier SnapshotApplier,
	cursor *coordinationCursor,
	head snapshot.Envelope,
) error {
	target, err := snapshot.Verify(head, cfg.RootPublicKey, cfg.NetworkID)
	if err != nil {
		return fmt.Errorf("verify snapshot head: %w", err)
	}
	// Authenticate before comparing attacker-supplied hashes for replay.
	sameHead := target.Revision == cursor.revision && bytes.Equal(head.Hash, cursor.hash)
	if sameHead && !cursor.needsApply {
		return nil
	}
	if target.Revision <= cursor.revision && !sameHead {
		return snapshot.ErrRevisionRollback
	}
	revision, hash := cursor.revision, bytes.Clone(cursor.hash)
	envelope := head
	for revision < target.Revision {
		page, err := fetchSnapshotHistory(ctx, cfg, revision, hash)
		if err != nil {
			return fmt.Errorf("fetch snapshot history after %d: %w", revision, err)
		}
		if len(page) == 0 {
			return snapshot.ErrRevisionGap
		}
		for _, next := range page {
			if err := snapshot.VerifyNext(
				next,
				cfg.RootPublicKey,
				cfg.NetworkID,
				revision,
				hash,
			); err != nil {
				return fmt.Errorf("verify history after %d: %w", revision, err)
			}
			revision++
			hash = bytes.Clone(next.Hash)
			envelope = next
			if revision == target.Revision {
				break
			}
		}
	}
	if !bytes.Equal(hash, head.Hash) {
		return snapshot.ErrPreviousHash
	}
	prepared, err := prepareSnapshotState(cfg.StatePath, envelope)
	if err != nil {
		return fmt.Errorf("%w: prepare: %w", ErrSnapshotState, err)
	}
	defer prepared.abort()
	if err := applyVerifiedSnapshot(ctx, applier, envelope, target); err != nil {
		return fmt.Errorf("apply snapshot revision %d: %w", target.Revision, err)
	}
	if err := prepared.commit(); err != nil {
		return fmt.Errorf("%w: commit after apply: %w", ErrSnapshotState, err)
	}
	cursor.revision, cursor.hash = revision, hash
	cursor.needsApply = false
	return nil
}
