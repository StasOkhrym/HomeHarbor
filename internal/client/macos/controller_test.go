package macos

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/snapshot"
)

type recordingHelper struct {
	requests []HelperRequest
	err      error
}

func (h *recordingHelper) Execute(_ context.Context, request HelperRequest) error {
	data, _ := json.Marshal(request)
	var copy HelperRequest

	if err := json.Unmarshal(data, &copy); err != nil {
		return err
	}

	h.requests = append(h.requests, copy)

	return h.err
}

func TestNativeControllerRequiresSignedEnvelopeAndCopiesTrust(t *testing.T) {
	authority, envelope, _, _, private := nativeFixtureWithKey(t)
	helper := &recordingHelper{}
	controller, err := NewController(authority, private, time.Second, helper)
	if err != nil {
		t.Fatal(err)
	}

	if err := controller.Apply(context.Background(), snapshot.NetworkSnapshot{}); err == nil {
		t.Fatal("decoded unsigned state reached privileged helper")
	}

	if len(helper.requests) != 0 {
		t.Fatal("construction or unsigned apply caused native effects")
	}

	// Caller mutation cannot replace the controller's startup trust anchor.
	authority.Root[0] ^= 1

	if err := controller.ApplySigned(
		context.Background(),
		envelope,
		snapshot.NetworkSnapshot{},
	); err != nil {
		t.Fatal(err)
	}

	if len(helper.requests) != 1 {
		t.Fatal("verified signed state was not submitted")
	}

	request := helper.requests[0]

	if request.Version != 1 || request.Action != "apply" || request.PrivateKey != private ||
		request.Plan.DeviceID != "client-1" || request.Plan.Routes[0].String() != "172.29.50.0/24" ||
		request.Plan.Revision != 1 || request.Plan.Revoked {
		t.Fatal("native request did not derive from the signed envelope")
	}
}

func TestNativeControllerRecoversFailedApplyAndRetriesFailedClose(t *testing.T) {
	authority, envelope, _, _, private := nativeFixtureWithKey(t)
	helper := &recordingHelper{}
	controller, err := NewController(authority, private, time.Second, helper)
	if err != nil {
		t.Fatal(err)
	}

	if err := controller.Close(
		context.Background(),
	); err != nil || len(helper.requests) != 1 ||
		helper.requests[0].Action != "close" {
		t.Fatal("startup did not recover previous process ownership")
	}

	failure := errors.New("helper rejected apply")
	helper.err = failure

	if err := controller.ApplySigned(
		context.Background(),
		envelope,
		snapshot.NetworkSnapshot{},
	); !errors.Is(
		err,
		failure,
	) {
		t.Fatalf("failed apply reported success: %v", err)
	}

	if err := controller.Close(context.Background()); !errors.Is(err, failure) {
		t.Fatalf("failed cleanup did not retain retry state: %v", err)
	}

	helper.err = nil

	if err := controller.Close(context.Background()); err != nil {
		t.Fatal(err)
	}

	if err := controller.Close(context.Background()); err != nil || len(helper.requests) != 4 {
		t.Fatal("completed cleanup was retried or failed cleanup was forgotten")
	}

	for _, request := range helper.requests[2:] {
		if request.Action != "close" || request.PrivateKey != "" || request.Plan.Revision != 0 {
			t.Fatal("cleanup carried private or caller-selected desired state")
		}
	}
}

func TestNativeControllerSendsSignedRevocationWithoutPrivateKey(t *testing.T) {
	authority, envelope, _, signing, private := nativeFixtureWithKey(t)

	value, err := snapshot.Verify(envelope, authority.Root, authority.NetworkID)
	if err != nil {
		t.Fatal(err)
	}

	value.Revision = 2
	value.Devices = value.Devices[1:]

	revoked, err := snapshot.Sign(value, signing, "root-1")
	if err != nil {
		t.Fatal(err)
	}

	helper := &recordingHelper{}
	controller, err := NewController(authority, private, time.Second, helper)
	if err != nil {
		t.Fatal(err)
	}

	if err := controller.ApplySigned(context.Background(), revoked, value); err != nil {
		t.Fatal(err)
	}

	if len(helper.requests) != 1 || !helper.requests[0].Plan.Revoked ||
		helper.requests[0].PrivateKey != "" {
		t.Fatal("signed removal retained native identity or omitted teardown")
	}
}

func TestNativeControllerClosesPreviousProcessOwnershipBeforeApply(t *testing.T) {
	authority, _, _, _, private := nativeFixtureWithKey(t)
	helper := &recordingHelper{}
	controller, err := NewController(authority, private, time.Second, helper)
	if err != nil {
		t.Fatal(err)
	}

	if err := controller.Close(context.Background()); err != nil {
		t.Fatal(err)
	}

	if len(helper.requests) != 1 || helper.requests[0].Action != "close" ||
		helper.requests[0].PrivateKey != "" {
		t.Fatal("startup cleanup ignored resources retained by an earlier process")
	}
}

func TestNativeCheckpointVerifiesHistoryWithoutApplyingOldBounds(t *testing.T) {
	authority, envelope, _, _, private := nativeFixtureWithKey(t)

	authority.Bounds.Private = netip.MustParsePrefix("172.29.50.0/25")
	helper := &recordingHelper{}
	controller, err := NewController(authority, private, time.Second, helper)
	if err != nil {
		t.Fatal(err)
	}

	if err := controller.VerifyRestore(
		context.Background(),
		envelope,
		snapshot.NetworkSnapshot{},
	); err != nil {
		t.Fatalf("valid historical lineage blocked a narrower current configuration: %v", err)
	}

	if err := controller.ApplySigned(
		context.Background(),
		envelope,
		snapshot.NetworkSnapshot{},
	); err == nil {
		t.Fatal("historical restore weakened current host permission bounds")
	}

	if len(helper.requests) != 0 {
		t.Fatal("historical checkpoint triggered an out-of-scope host effect")
	}
}
