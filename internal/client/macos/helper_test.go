package macos

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
)

func helperJSON(t *testing.T, request HelperRequest) []byte {
	t.Helper()

	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}

	return encoded
}

func TestHelperAppliesOnlyExactSignedPlanForProvisionedOwner(t *testing.T) {
	authority, envelope, plan := nativeFixture(t)
	policy := HelperPolicy{
		Authority:   authority,
		OwnerUID:    501,
		JournalPath: filepath.Join(t.TempDir(), "owner.json"),
	}
	request := HelperRequest{Version: 1, Action: "apply", Envelope: envelope, Plan: plan}
	native := &fakeNative{}
	if err := ExecuteHelper(
		context.Background(),
		bytes.NewReader(helperJSON(t, request)),
		policy,
		502,
		native,
	); err == nil {
		t.Fatal("foreign UID applied native networking")
	}
	if len(native.calls) != 0 {
		t.Fatalf("foreign UID caused native effects: %v", native.calls)
	}
	originalRoute := request.Plan.Routes[0]
	request.Plan.Routes[0] = netip.MustParsePrefix("172.29.50.80/32")
	if err := ExecuteHelper(
		context.Background(),
		bytes.NewReader(helperJSON(t, request)),
		policy,
		501,
		native,
	); err == nil {
		t.Fatal("changed plan passed the signed helper boundary")
	}
	if len(native.calls) != 0 {
		t.Fatalf("changed plan caused native effects: %v", native.calls)
	}
	request.Plan.Routes[0] = originalRoute
	if err := ExecuteHelper(
		context.Background(),
		bytes.NewReader(helperJSON(t, request)),
		policy,
		501,
		native,
	); err != nil {
		t.Fatalf("exact signed plan rejected: %v", err)
	}
	if len(native.calls) == 0 {
		t.Fatal("valid helper request did not apply native operations")
	}
}

func TestHelperRejectsUnboundedOrAmbiguousInputBeforeEffects(t *testing.T) {
	authority, envelope, plan := nativeFixture(t)
	policy := HelperPolicy{
		Authority:   authority,
		OwnerUID:    501,
		JournalPath: filepath.Join(t.TempDir(), "owner.json"),
	}
	request := helperJSON(
		t,
		HelperRequest{Version: 1, Action: "apply", Envelope: envelope, Plan: plan},
	)
	for _, input := range [][]byte{
		append(bytes.Clone(request), []byte(` {"version":1,"action":"close"}`)...),
		[]byte(`{"version":1,"version":1,"action":"close"}`),
		append(bytes.Clone(request[:len(request)-1]), []byte(`,"shell":"touch /tmp/escaped"}`)...),
		[]byte(strings.Repeat(" ", MaxHelperRequestBytes+1)),
	} {
		native := &fakeNative{}
		if err := ExecuteHelper(
			context.Background(),
			bytes.NewReader(input),
			policy,
			501,
			native,
		); err == nil {
			t.Fatal("malformed or oversized helper request accepted")
		}
		if len(native.calls) != 0 {
			t.Fatalf("malformed request caused native effects: %v", native.calls)
		}
	}
}

func TestHelperCloseCannotCarryAnUnsignedPlan(t *testing.T) {
	authority, envelope, plan := nativeFixture(t)
	policy := HelperPolicy{
		Authority:   authority,
		OwnerUID:    501,
		JournalPath: filepath.Join(t.TempDir(), "owner.json"),
	}
	native := &fakeNative{}
	request := HelperRequest{Version: 1, Action: "close", Envelope: envelope, Plan: plan}
	if err := ExecuteHelper(
		context.Background(),
		bytes.NewReader(helperJSON(t, request)),
		policy,
		501,
		native,
	); err == nil {
		t.Fatal("close accepted a caller-selected plan")
	}
	if len(native.calls) != 0 {
		t.Fatalf("invalid close caused native effects: %v", native.calls)
	}
}
