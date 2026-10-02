package coordination

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"strconv"
	"strings"

	"github.com/StasOkhrym/homeharbor/internal/control/devices"
	"github.com/StasOkhrym/homeharbor/internal/control/snapshots"
	controlprotocol "github.com/StasOkhrym/homeharbor/internal/protocol"
	"github.com/StasOkhrym/homeharbor/internal/snapshot"
)

const maxSnapshotEnvelopeBytes = 64 << 10

type SnapshotHistoryProvider interface {
	SnapshotProvider
	History(context.Context, uint64, int) ([]snapshot.Envelope, error)
}

// ServeHistory is mounted by the HTTP composition layer at GET
// /api/v1/coordination/snapshots. It authenticates devices independently of
// browser/companion authorization and returns bounded JSON arrays, never WS batches.
func (h *Handler) ServeHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.Auth == nil {
		http.Error(w, "device authentication unavailable", http.StatusServiceUnavailable)
		return
	}
	authorization := r.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, "Bearer ") {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	device, err := h.Auth.Authenticate(r.Context(), strings.TrimPrefix(authorization, "Bearer "))
	if err != nil || device.ID == "" || device.Status != devices.StatusActive {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	provider := h.History
	if provider == nil {
		http.Error(w, "snapshot history unavailable", http.StatusServiceUnavailable)
		return
	}
	after := uint64(0)
	if raw := r.URL.Query().Get("after_revision"); raw != "" {
		after, err = strconv.ParseUint(raw, 10, 64)
		if err != nil || after > math.MaxInt64 {
			http.Error(w, "invalid history cursor", http.StatusBadRequest)
			return
		}
	}
	limit := snapshots.MaxHistoryPageSize
	if raw := r.URL.Query().Get("limit"); raw != "" {
		limit, err = strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > snapshots.MaxHistoryPageSize {
			http.Error(w, "invalid history limit", http.StatusBadRequest)
			return
		}
	}
	if after > 0 {
		hash, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("after_hash"))
		if err != nil || len(hash) != 32 {
			http.Error(w, "history cursor hash required", http.StatusBadRequest)
			return
		}
		predecessor, err := provider.History(r.Context(), after-1, 1)
		if err != nil || len(predecessor) != 1 || !bytes.Equal(predecessor[0].Hash, hash) {
			http.Error(w, "history cursor conflict", http.StatusConflict)
			return
		}
	} else if r.URL.Query().Get("after_hash") != "" {
		http.Error(w, "genesis cursor has no hash", http.StatusBadRequest)
		return
	}
	page, err := provider.History(r.Context(), after, limit)
	if err != nil {
		status := http.StatusServiceUnavailable
		if errors.Is(err, snapshots.ErrHistoryCursor) || errors.Is(err, snapshot.ErrRevisionGap) {
			status = http.StatusConflict
		}
		http.Error(w, "snapshot history unavailable", status)
		return
	}
	if len(page) > limit {
		http.Error(w, "snapshot history exceeds page limit", http.StatusServiceUnavailable)
		return
	}
	for _, envelope := range page {
		data, err := json.Marshal(envelope)
		if err != nil || len(data) > maxSnapshotEnvelopeBytes {
			http.Error(w, "snapshot history exceeds envelope limit", http.StatusServiceUnavailable)
			return
		}
	}
	if page == nil {
		page = []snapshot.Envelope{}
	}
	data, err := json.Marshal(page)
	if err != nil || len(data) > snapshots.MaxHistoryPageSize*(maxSnapshotEnvelopeBytes+1)+2 {
		http.Error(w, "snapshot history exceeds body limit", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

func snapshotMessage(envelope snapshot.Envelope) (controlprotocol.Message, error) {
	payload, err := json.Marshal(envelope)
	if err != nil {
		return controlprotocol.Message{}, err
	}

	message := controlprotocol.Message{Type: "network.snapshot", Payload: payload}
	frame, err := json.Marshal(message)
	if err != nil {
		return controlprotocol.Message{}, err
	}
	if len(frame) > maxSnapshotEnvelopeBytes {
		return controlprotocol.Message{}, errors.New("snapshot WebSocket frame exceeds 64 KiB")
	}

	return message, nil
}
