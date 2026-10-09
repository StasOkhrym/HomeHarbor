package main

import (
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/platform/config"
)

func TestRelayHardDrainOutlivesMaximumHTTPShutdown(t *testing.T) {
	runtime := config.DefaultRuntime(true)
	runtime.ShutdownTimeout = time.Minute

	if err := runtime.Validate(); err != nil {
		t.Fatalf("maximum HTTP shutdown should be valid: %v", err)
	}

	if relayDrainTimeout <= runtime.ShutdownTimeout {
		t.Fatalf("relay hard drain %s preempts allowed HTTP shutdown %s",
			relayDrainTimeout, runtime.ShutdownTimeout)
	}
}
