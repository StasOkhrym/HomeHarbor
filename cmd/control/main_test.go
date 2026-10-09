package main

import (
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/platform/config"
)

func TestControlHardDrainAllowsMaximumShutdownAndCleanup(t *testing.T) {
	runtime := config.DefaultRuntime(false)
	runtime.ShutdownTimeout = time.Minute
	runtime.CleanupTimeout = time.Minute

	if err := runtime.Validate(); err != nil {
		t.Fatalf("maximum runtime durations should be valid: %v", err)
	}

	if controlDrainTimeout <= runtime.ShutdownTimeout+runtime.CleanupTimeout {
		t.Fatalf(
			"control hard drain %s preempts allowed shutdown %s plus cleanup %s",
			controlDrainTimeout, runtime.ShutdownTimeout, runtime.CleanupTimeout,
		)
	}
}
