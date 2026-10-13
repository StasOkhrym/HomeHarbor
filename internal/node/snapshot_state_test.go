package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/snapshot"
)

type stateApplier struct {
	revisions []uint64
	fail      error
	hook      func()
}

type signedStateApplier struct {
	envelopes [][]byte
}

type deferredStateApplier struct {
	verified []uint64
	applied  []uint64
	fail     error
}

func (*deferredStateApplier) Apply(context.Context, snapshot.NetworkSnapshot) error {
	return errors.New("deferred owner requires a signed envelope")
}

func (a *deferredStateApplier) VerifyRestore(
	_ context.Context,
	_ snapshot.Envelope,
	value snapshot.NetworkSnapshot,
) error {
	a.verified = append(a.verified, value.Revision)
	return nil
}

func (a *deferredStateApplier) ApplySigned(
	_ context.Context,
	_ snapshot.Envelope,
	value snapshot.NetworkSnapshot,
) error {
	if a.fail != nil {
		return a.fail
	}

	a.applied = append(a.applied, value.Revision)

	return nil
}

func TestDeferredRestoreAppliesMatchingAuthenticatedHeadAndRetriesFailure(t *testing.T) {
	public, history := signedHistory(t, 1)
	ctx := context.Background()
	cfg := CoordinationConfig{
		NetworkID:     "home",
		RootPublicKey: public,
		StatePath:     filepath.Join(t.TempDir(), "head.json"),
	}

	prepared, err := prepareSnapshotState(cfg.StatePath, history[0])
	if err != nil {
		t.Fatal(err)
	}

	if err := prepared.commit(); err != nil {
		t.Fatal(err)
	}

	applier := &deferredStateApplier{}

	cursor, err := restoreSnapshotCursor(ctx, cfg, applier)

	if err != nil || len(applier.applied) != 0 ||
		!reflect.DeepEqual(applier.verified, []uint64{1}) {
		t.Fatalf(
			"checkpoint applied host state before authenticated head: applied=%v verified=%v err=%v",
			applier.applied,
			applier.verified,
			err,
		)
	}

	applier.fail = errors.New("root owner rejected stale or failed host apply")

	if err := reconcileSnapshotHead(ctx, cfg, applier, &cursor, history[0]); err == nil {
		t.Fatal("matching head suppressed required host restoration")
	}

	applier.fail = nil

	if err := reconcileSnapshotHead(ctx, cfg, applier, &cursor, history[0]); err != nil {
		t.Fatal(err)
	}

	if err := reconcileSnapshotHead(
		ctx,
		cfg,
		applier,
		&cursor,
		history[0],
	); err != nil ||
		!reflect.DeepEqual(applier.applied, []uint64{1}) {
		t.Fatalf("matching head was not applied exactly once: %v, %v", applier.applied, err)
	}
}

func TestDeferredRestoreCatchesUpWithoutReapplyingOlderCheckpoint(t *testing.T) {
	public, history := signedHistory(t, 2)
	var requested []uint64

	server := historyServer(t, history, nil, &requested)
	defer server.Close()

	cfg := CoordinationConfig{
		URL:           "ws" + server.URL[len("http"):],
		Credential:    "credential",
		NetworkID:     "home",
		RootPublicKey: public,
		StatePath:     filepath.Join(t.TempDir(), "head.json"),
	}

	prepared, err := prepareSnapshotState(cfg.StatePath, history[0])
	if err != nil {
		t.Fatal(err)
	}

	if err := prepared.commit(); err != nil {
		t.Fatal(err)
	}

	applier := &deferredStateApplier{}

	cursor, err := restoreSnapshotCursor(context.Background(), cfg, applier)
	if err != nil {
		t.Fatal(err)
	}

	if err := reconcileSnapshotHead(
		context.Background(),
		cfg,
		applier,
		&cursor,
		history[1],
	); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(applier.applied, []uint64{2}) ||
		!reflect.DeepEqual(requested, []uint64{1}) ||
		cursor.revision != 2 {
		t.Fatalf(
			"older checkpoint reapplied: applied=%v requested=%v cursor=%d",
			applier.applied,
			requested,
			cursor.revision,
		)
	}
}

func (*signedStateApplier) Apply(context.Context, snapshot.NetworkSnapshot) error {
	return errors.New("signed owner was given only a decoded value")
}

func (a *signedStateApplier) ApplySigned(
	_ context.Context,
	envelope snapshot.Envelope,
	value snapshot.NetworkSnapshot,
) error {
	if value.Revision == 0 || len(envelope.Hash) == 0 {
		return errors.New("signed owner received an empty envelope")
	}

	a.envelopes = append(a.envelopes, bytes.Clone(envelope.Hash))

	return nil
}

func (a *stateApplier) Apply(_ context.Context, value snapshot.NetworkSnapshot) error {
	if a.fail != nil {
		return a.fail
	}

	a.revisions = append(a.revisions, value.Revision)
	if a.hook != nil {
		a.hook()
	}

	return nil
}

func signedHistory(t *testing.T, count int) (ed25519.PublicKey, []snapshot.Envelope) {
	t.Helper()

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	page := []snapshot.Envelope{}
	var hash []byte
	for i := 1; i <= count; i++ {
		value := snapshot.NetworkSnapshot{
			NetworkID:    "home",
			Revision:     uint64(i),
			PreviousHash: hash,
		}
		// Earlier revisions intentionally do not contain the joining node.
		if i == count {
			value.Devices = []snapshot.Device{
				{ID: "device-1", Role: "client", OverlayAddress: "100.64.0.2/32"},
			}
		}

		envelope, err := snapshot.Sign(value, private, "root")
		if err != nil {
			t.Fatal(err)
		}

		page = append(page, envelope)
		hash = envelope.Hash
	}

	return public, page
}

func historyServer(
	t *testing.T,
	page []snapshot.Envelope,
	transform func([]snapshot.Envelope) []snapshot.Envelope,
	cursors *[]uint64,
) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/coordination/snapshots" ||
			r.Header.Get("Authorization") != "Bearer credential" {
			t.Errorf("unauthenticated history request: %s", r.URL)

			w.WriteHeader(401)
			return
		}

		after, err := strconv.ParseUint(r.URL.Query().Get("after_revision"), 10, 64)
		if err != nil {
			t.Error(err)

			w.WriteHeader(400)
			return
		}

		*cursors = append(*cursors, after)

		limit, err := strconv.Atoi(r.URL.Query().Get("limit"))

		if err != nil || limit < 1 || limit > 16 {
			t.Errorf("limit=%d err=%v", limit, err)
		}

		result := []snapshot.Envelope{}
		for _, envelope := range page {
			value, _ := snapshot.Decode(envelope)
			if value.Revision > after {
				result = append(result, envelope)
				if len(result) == 2 {
					break
				}
			}
		}

		if transform != nil {
			result = transform(result)
		}

		_ = json.NewEncoder(w).Encode(result)
	}))
}

func TestSnapshotCatchUpVerifiesEveryPageAndAppliesOnlyTarget(t *testing.T) {
	public, history := signedHistory(t, 5)
	var cursors []uint64

	server := historyServer(t, history, nil, &cursors)
	defer server.Close()

	cfg := CoordinationConfig{
		URL:           "ws" + server.URL[len("http"):],
		Credential:    "credential",
		NetworkID:     "home",
		DeviceID:      "device-1",
		RootPublicKey: public,
		StatePath:     filepath.Join(t.TempDir(), "head.json"),
	}
	applier, cursor := &stateApplier{}, &coordinationCursor{}

	if err := reconcileSnapshotHead(
		context.Background(),
		cfg,
		applier,
		cursor,
		history[4],
	); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(cursors, []uint64{0, 2, 4}) ||
		!reflect.DeepEqual(applier.revisions, []uint64{5}) ||
		cursor.revision != 5 {
		t.Fatalf("requests=%v applied=%v cursor=%d", cursors, applier.revisions, cursor.revision)
	}

	info, err := os.Stat(cfg.StatePath)

	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("checkpoint mode=%v err=%v", info, err)
	}

	restoredApplier := &stateApplier{}

	restored, err := restoreSnapshotCursor(context.Background(), cfg, restoredApplier)

	if err != nil || restored.revision != 5 ||
		!reflect.DeepEqual(restoredApplier.revisions, []uint64{5}) {
		t.Fatalf("restore cursor=%v applied=%v err=%v", restored, restoredApplier.revisions, err)
	}

	if err := reconcileSnapshotHead(
		context.Background(),
		cfg,
		restoredApplier,
		&restored,
		history[4],
	); err != nil {
		t.Fatal(err)
	}

	if len(restoredApplier.revisions) != 1 || len(cursors) != 3 {
		t.Fatal("valid same head fetched or reapplied")
	}

	forged := history[4]
	forged.Signature = append([]byte(nil), forged.Signature...)
	forged.Signature[0] ^= 1

	if err := reconcileSnapshotHead(
		context.Background(),
		cfg,
		restoredApplier,
		&restored,
		forged,
	); !errors.Is(
		err,
		snapshot.ErrInvalidSignature,
	) {
		t.Fatalf("same-hash forged replay: %v", err)
	}
}

func TestSignedOwnerReceivesExactEnvelopeOnCatchUpAndRestore(t *testing.T) {
	root, history := signedHistory(t, 3)
	var cursors []uint64

	server := historyServer(t, history, nil, &cursors)
	defer server.Close()

	cfg := CoordinationConfig{
		URL: "ws" + server.URL[len("http"):], Credential: "credential",
		NetworkID: "home", DeviceID: "device-1", RootPublicKey: root,
		StatePath: filepath.Join(t.TempDir(), "head.json"),
	}
	owner := &signedStateApplier{}
	cursor := &coordinationCursor{}

	if err := reconcileSnapshotHead(
		context.Background(),
		cfg,
		owner,
		cursor,
		history[2],
	); err != nil {
		t.Fatal(err)
	}

	if len(owner.envelopes) != 1 || !bytes.Equal(owner.envelopes[0], history[2].Hash) {
		t.Fatal("history path lost the exact verified signed envelope")
	}

	restarted := &signedStateApplier{}

	if _, err := restoreSnapshotCursor(context.Background(), cfg, restarted); err != nil {
		t.Fatal(err)
	}

	if len(restarted.envelopes) != 1 || !bytes.Equal(restarted.envelopes[0], history[2].Hash) {
		t.Fatal("restore path lost the exact persisted signed envelope")
	}
}

func TestSnapshotCatchUpRejectsMissingGappedAndTamperedHistory(t *testing.T) {
	public, history := signedHistory(t, 4)
	for _, test := range []struct {
		name   string
		change func([]snapshot.Envelope) []snapshot.Envelope
	}{
		{"empty", func([]snapshot.Envelope) []snapshot.Envelope { return []snapshot.Envelope{} }},
		{"gap", func(page []snapshot.Envelope) []snapshot.Envelope { return page[1:] }},
		{"signature", func(page []snapshot.Envelope) []snapshot.Envelope {
			page[0].Signature = append([]byte(nil), page[0].Signature...)
			page[0].Signature[0] ^= 1

			return page
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var cursors []uint64

			server := historyServer(t, history, test.change, &cursors)
			defer server.Close()

			cfg := CoordinationConfig{
				URL:           "ws" + server.URL[len("http"):],
				Credential:    "credential",
				NetworkID:     "home",
				RootPublicKey: public,
				StatePath:     filepath.Join(t.TempDir(), "head.json"),
			}
			applier, cursor := &stateApplier{}, &coordinationCursor{}

			if err := reconcileSnapshotHead(
				context.Background(),
				cfg,
				applier,
				cursor,
				history[3],
			); err == nil {
				t.Fatal("invalid history accepted")
			}

			if len(applier.revisions) != 0 || cursor.revision != 0 {
				t.Fatal("invalid history mutated state")
			}

			if _, err := os.Stat(cfg.StatePath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("checkpoint exists: %v", err)
			}
		})
	}
}

func TestSnapshotCheckpointFailureAndTrustBinding(t *testing.T) {
	public, history := signedHistory(t, 1)
	path := filepath.Join(t.TempDir(), "head.json")

	if err := persistSnapshotState(path, history[0]); err != nil {
		t.Fatal(err)
	}

	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	for _, cfg := range []CoordinationConfig{
		{StatePath: path, RootPublicKey: other, NetworkID: "home"},
		{StatePath: path, RootPublicKey: public, NetworkID: "other"},
	} {
		a := &stateApplier{}

		if _, err := restoreSnapshotCursor(
			context.Background(),
			cfg,
			a,
		); !errors.Is(err, ErrSnapshotState) ||
			len(a.revisions) != 0 {
			t.Fatalf("untrusted checkpoint err=%v applied=%v", err, a.revisions)
		}
	}

	var cursors []uint64

	server := historyServer(t, history, nil, &cursors)
	defer server.Close()

	cfg := CoordinationConfig{
		URL:           "ws" + server.URL[len("http"):],
		Credential:    "credential",
		NetworkID:     "home",
		RootPublicKey: public,
		StatePath:     t.TempDir(),
	}
	a, cursor := &stateApplier{}, &coordinationCursor{}

	if err := reconcileSnapshotHead(
		context.Background(),
		cfg,
		a,
		cursor,
		history[0],
	); !errors.Is(
		err,
		ErrSnapshotState,
	) {
		t.Fatalf("persistence error=%v", err)
	}

	if cursor.revision != 0 || len(a.revisions) != 0 {
		t.Fatal("failed state preparation applied or advanced cursor")
	}

	cfg.StatePath = path
	a.fail = errors.New("kernel rejected target")

	if err := reconcileSnapshotHead(context.Background(), cfg, a, cursor, history[0]); err == nil {
		t.Fatal("application failure accepted")
	}

	if cursor.revision != 0 {
		t.Fatal("failed application advanced cursor")
	}

	loaded, err := loadSnapshotState(path, public, "home")

	if err != nil || !reflect.DeepEqual(loaded.Hash, history[0].Hash) {
		t.Fatalf("failed application changed checkpoint: %v", err)
	}
}

func TestSnapshotCheckpointCommitFailureKeepsCursorAndStopsLoop(t *testing.T) {
	public, history := signedHistory(t, 1)
	var requests []uint64

	server := historyServer(t, history, nil, &requests)
	defer server.Close()

	path := filepath.Join(t.TempDir(), "head.json")
	cfg := CoordinationConfig{
		URL:           "ws" + server.URL[len("http"):],
		Credential:    "credential",
		NetworkID:     "home",
		RootPublicKey: public,
		StatePath:     path,
	}
	applier := &stateApplier{hook: func() {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}}
	cursor := coordinationCursor{}

	if err := reconcileSnapshotHead(
		context.Background(),
		cfg,
		applier,
		&cursor,
		history[0],
	); !errors.Is(
		err,
		ErrSnapshotState,
	) {
		t.Fatalf("commit failure=%v", err)
	}

	if cursor.revision != 0 || len(applier.revisions) != 1 {
		t.Fatalf("cursor=%d applied=%v", cursor.revision, applier.revisions)
	}

	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}

	if len(entries) != 1 || entries[0].Name() != "head.json" {
		t.Fatalf("abandoned temporary checkpoint: %v", entries)
	}

	// Bad local state is terminal before any network reconnect attempt.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if err := RunCoordinationLoop(ctx, cfg, &stateApplier{}); !errors.Is(err, ErrSnapshotState) {
		t.Fatalf("loop persistence failure=%v", err)
	}
}
