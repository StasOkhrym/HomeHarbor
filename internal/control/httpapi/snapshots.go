package httpapi

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/sokhrym/go-tunnels/internal/protocol"
	"github.com/sokhrym/go-tunnels/internal/snapshot"
)

func (s *Server) publishSnapshot(w http.ResponseWriter, r *http.Request) {
	var envelope snapshot.Envelope
	if !decodeJSON(w, r, &envelope) {
		return
	}

	if err := s.snapshots.Publish(r.Context(), envelope); err != nil {
		writeError(w, http.StatusBadRequest, "invalid signed snapshot")
		return
	}

	if s.snapshotBroadcaster != nil {
		s.snapshotBroadcaster.BroadcastSnapshot(r.Context(), envelope)
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) latestSnapshot(w http.ResponseWriter, r *http.Request) {
	envelope, err := s.snapshots.Latest(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "signed snapshot unavailable")
		return
	}

	writeJSON(w, http.StatusOK, envelope)
}

func (s *Server) issueCompanionChallenge(w http.ResponseWriter, r *http.Request) {
	nonce, expiresAt, err := s.companionChallenges.issue(r.Context(), time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "companion challenge unavailable")
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"nonce": nonce, "expires_at": expiresAt})
}

func (s *Server) companionSnapshot(w http.ResponseWriter, r *http.Request) {
	if s.companionChallenges == nil || len(s.companionRoot) != ed25519.PublicKeySize {
		writeError(w, http.StatusNotFound, "companion access is not configured")
		return
	}
	nonce := r.Header.Get("X-Go-Tunnels-Companion-Nonce")
	keyID := r.Header.Get("X-Go-Tunnels-Companion-Key-ID")
	signature, err := base64.RawURLEncoding.DecodeString(r.Header.Get("X-Go-Tunnels-Companion-Signature"))
	if err != nil || protocol.VerifyCompanionRequest(http.MethodGet, companionSnapshotPath, nonce, keyID, signature, s.companionRoot) != nil {
		writeError(w, http.StatusUnauthorized, "invalid companion request")
		return
	}
	consumed, consumeErr := s.companionChallenges.consume(r.Context(), nonce, time.Now().UTC())
	if consumeErr != nil {
		writeError(w, http.StatusServiceUnavailable, "security state unavailable")
		return
	}
	if !consumed {
		writeError(w, http.StatusUnauthorized, "invalid companion request")
		return
	}
	envelope, err := s.snapshots.Latest(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "signed snapshot unavailable")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, envelope)
}
