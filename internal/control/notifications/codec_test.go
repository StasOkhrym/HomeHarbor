package notifications_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/StasOkhrym/homeharbor/internal/control/notifications"
)

func mailFixture(t *testing.T) (*notifications.Codec, notifications.Intent) {
	t.Helper()

	codec, err := notifications.NewCodec(
		bytes.Repeat([]byte{7}, 32),
		"https://control.example.test",
	)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

	return codec, notifications.Intent{
		ID:        uuid.NewString(),
		AccountID: "account-a",
		Kind:      notifications.PasswordReset,
		To:        "owner@example.test",
		Token:     base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)),
		CreatedAt: now,
		ExpiresAt: now.Add(15 * time.Minute),
	}
}

func TestMailPayloadIsSealedAndLogicalRetriesStayStable(t *testing.T) {
	codec, intent := mailFixture(t)

	first, err := codec.Prepare(intent)
	if err != nil {
		t.Fatal(err)
	}

	second, err := codec.Prepare(intent)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(first.Ciphertext, second.Ciphertext) || first.Fingerprint != second.Fingerprint {
		t.Fatal("logical retry lost its identity or encryption nonce reused")
	}

	for _, secret := range []string{intent.To, intent.Token} {
		if bytes.Contains(first.Ciphertext, []byte(secret)) {
			t.Fatal("plaintext in delivery payload")
		}
	}

	data, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(string(data), intent.To) || strings.Contains(string(data), intent.Token) ||
		strings.Contains(string(data), "Ciphertext") {
		t.Fatal("private delivery data JSON-logged")
	}

	message, err := codec.Render(first, intent.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}

	if message.To != intent.To || message.ID != intent.ID ||
		!strings.Contains(
			message.Text,
			"https://control.example.test/admin/reset-password#token="+intent.Token,
		) ||
		strings.Contains(message.Text, "?token=") {
		t.Fatal("unsafe or wrong reset email")
	}

	again, err := codec.Render(second, intent.CreatedAt)

	if err != nil || again.ID != message.ID || again.Text != message.Text ||
		again.Date != message.Date {
		t.Fatal("retry changed the logical email", err)
	}
}

func TestMailPayloadRejectsMetadataSwapsAndExpiry(t *testing.T) {
	codec, intent := mailFixture(t)

	original, err := codec.Prepare(intent)
	if err != nil {
		t.Fatal(err)
	}

	for _, change := range []string{"id", "account", "kind", "expiry", "fingerprint", "ciphertext", "expired"} {
		t.Run(change, func(t *testing.T) {
			prepared := original

			prepared.Ciphertext = bytes.Clone(original.Ciphertext)
			now := intent.CreatedAt
			switch change {
			case "id":
				prepared.ID = uuid.NewString()
			case "account":
				prepared.AccountID = "account-b"
			case "kind":
				prepared.Kind = notifications.AdminInvitation
			case "expiry":
				prepared.ExpiresAt = prepared.ExpiresAt.Add(time.Minute)
			case "fingerprint":
				prepared.Fingerprint[0] ^= 1
			case "ciphertext":
				prepared.Ciphertext[len(prepared.Ciphertext)-1] ^= 1
			case "expired":
				now = intent.ExpiresAt
			}

			if _, err := codec.Render(
				prepared,
				now,
			); !errors.Is(
				err,
				notifications.ErrInvalidPayload,
			) {
				t.Fatal("invalid private delivery rendered", err)
			}
		})
	}
}

func TestMailIntentRejectsUnsafeAddressesTokensAndOrigins(t *testing.T) {
	codec, intent := mailFixture(t)
	for _, change := range []string{"recipient", "injected-recipient", "token", "kind", "expiry", "id"} {
		t.Run(change, func(t *testing.T) {
			candidate := intent
			switch change {
			case "recipient":
				candidate.To = "Display <owner@example.test>"
			case "injected-recipient":
				candidate.To = "owner@example.test\r\nBcc:other@example.test"
			case "token":
				candidate.Token = "short"
			case "kind":
				candidate.Kind = "unknown"
			case "expiry":
				candidate.ExpiresAt = candidate.CreatedAt.Add(16 * time.Minute)
			case "id":
				candidate.ID = "not-a-uuid"
			}

			if _, err := codec.Prepare(
				candidate,
			); !errors.Is(
				err,
				notifications.ErrInvalidPayload,
			) {
				t.Fatal("unsafe intent admitted", err)
			}
		})
	}

	for _, origin := range []string{"http://control.example.test", "https://user:password@control.example.test", "https://control.example.test/path", "https://control.example.test?secret=x", "https://control.example.test#fragment"} {
		if _, err := notifications.NewCodec(bytes.Repeat([]byte{7}, 32), origin); err == nil {
			t.Fatal("unsafe link origin admitted")
		}
	}
}

func TestMailPreparationSurvivesSQLTimestampPrecision(t *testing.T) {
	codec, intent := mailFixture(t)
	intent.CreatedAt = intent.CreatedAt.Add(123456789 * time.Nanosecond)
	intent.ExpiresAt = intent.CreatedAt.Add(15 * time.Minute)

	prepared, err := codec.Prepare(intent)
	if err != nil {
		t.Fatal(err)
	}

	prepared.CreatedAt = prepared.CreatedAt.Truncate(time.Microsecond)

	prepared.ExpiresAt = prepared.ExpiresAt.Truncate(time.Microsecond)

	if _, err := codec.Render(prepared, intent.CreatedAt); err != nil {
		t.Fatal("normal SQL timestamp precision invalidated an authentic payload", err)
	}
}

func TestMailRetryKeepsOriginalControlOrigin(t *testing.T) {
	codec, intent := mailFixture(t)

	prepared, err := codec.Prepare(intent)
	if err != nil {
		t.Fatal(err)
	}

	changed, err := notifications.NewCodec(
		bytes.Repeat([]byte{7}, 32),
		"https://new-control.example.test",
	)
	if err != nil {
		t.Fatal(err)
	}

	message, err := changed.Render(prepared, intent.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(message.Text, "https://control.example.test/admin/reset-password#token=") {
		t.Fatal("restart silently changed the queued credential destination")
	}
}
