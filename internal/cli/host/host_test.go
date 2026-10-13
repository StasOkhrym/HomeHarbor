package host

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/StasOkhrym/homeharbor/internal/platform/lifecycle"
)

func TestExecuteClassifiesAndRoutesOutput(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		run  func(*cobra.Command, []string) error
		code int
		want string
	}{
		{name: "help", args: []string{"--help"}, code: 0, want: "Usage:"},
		{name: "version", args: []string{"--version"}, code: 0, want: "version"},
		{name: "syntax", args: []string{"extra"}, code: 2, want: "unknown command"},
		{name: "unknown flag", args: []string{"--missing"}, code: 2, want: "unknown flag"},
		{name: "runtime", run: func(*cobra.Command, []string) error { return errors.New("runtime failed") }, code: 1, want: "runtime failed"},
		{name: "runtime resembling syntax", run: func(*cobra.Command, []string) error {
			return errors.New("unknown command from remote service")
		}, code: 1, want: "unknown command from remote service"},
		{name: "interrupted", run: func(*cobra.Command, []string) error { return context.Canceled }, code: 130, want: "context canceled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			root := &cobra.Command{Use: "sample", Args: NoArgs, RunE: tc.run}
			if root.RunE == nil {
				root.RunE = func(*cobra.Command, []string) error { t.Fatal("help/version/syntax ran command"); return nil }
			}

			got := Execute(context.Background(), tc.args, &stdout, &stderr, root)

			if got != tc.code {
				t.Fatalf(
					"exit code %d, want %d; stdout=%q stderr=%q",
					got,
					tc.code,
					stdout.String(),
					stderr.String(),
				)
			}

			output := stderr.String()
			if tc.code == 0 {
				output = stdout.String()
			}

			if !strings.Contains(output, tc.want) {
				t.Fatalf("output %q does not contain %q", output, tc.want)
			}
		})
	}
}

func TestExecuteDoesNotReportSuccessAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	root := &cobra.Command{
		Use: "finite",
		RunE: func(*cobra.Command, []string) error {
			cancel()
			return nil
		},
	}
	var stdout, stderr bytes.Buffer

	if code := Execute(ctx, nil, &stdout, &stderr, root); code != 130 {
		t.Fatalf("canceled command returned %d; stderr=%q", code, stderr.String())
	}
}

func TestSignalContextSecondSignalAndDeadlineAreHardFailures(t *testing.T) {
	for _, trigger := range []string{"second signal", "drain deadline"} {
		t.Run(trigger, func(t *testing.T) {
			signals := make(chan struct{}, 2)
			hard := make(chan int, 1)

			ctx, stop := signalContext(
				context.Background(),
				signals,
				20*time.Millisecond,
				func(code int) { hard <- code },
			)
			defer stop()

			signals <- struct{}{}
			select {
			case <-ctx.Done():
			case <-time.After(time.Second):
				t.Fatal("first signal did not cancel")
			}

			if trigger == "second signal" {
				signals <- struct{}{}
			}

			select {
			case code := <-hard:
				if code != 130 {
					t.Fatalf("hard-exit code = %d", code)
				}
			case <-time.After(time.Second):
				t.Fatal("hard exit was not requested")
			}
		})
	}
}

func TestConfiguredDrainReplacesDefaultBeforeCancellation(t *testing.T) {
	signals := make(chan struct{}, 2)
	hard := make(chan int, 1)

	ctx, stop := signalContext(
		context.Background(),
		signals,
		time.Minute,
		func(code int) { hard <- code },
	)
	defer stop()

	if err := ConfigureDrain(ctx, 15*time.Millisecond); err != nil {
		t.Fatal(err)
	}

	signals <- struct{}{}
	select {
	case code := <-hard:
		if code != 130 {
			t.Fatalf("hard exit = %d", code)
		}
	case <-time.After(time.Second):
		t.Fatal("configured drain was ignored")
	}
}

func TestDrainCannotBeExtendedAfterFirstSignal(t *testing.T) {
	signals := make(chan struct{}, 2)
	hard := make(chan int, 1)

	ctx, stop := signalContext(
		context.Background(),
		signals,
		20*time.Millisecond,
		func(code int) { hard <- code },
	)
	defer stop()

	signals <- struct{}{}
	<-ctx.Done()

	if err := ConfigureDrain(ctx, time.Minute); !errors.Is(err, context.Canceled) {
		t.Fatalf("draining process allowed reconfiguration: %v", err)
	}

	select {
	case <-hard:
	case <-time.After(time.Second):
		t.Fatal("active drain deadline was extended")
	}
}

func TestInvalidDrainDoesNotChangeLiveContext(t *testing.T) {
	ctx, stop := signalContext(
		context.Background(),
		make(chan struct{}),
		time.Minute,
		func(int) { t.Error("unexpected hard exit") },
	)
	defer stop()

	for _, duration := range []time.Duration{0, -time.Second} {
		if err := ConfigureDrain(ctx, duration); err == nil {
			t.Fatal("nonpositive drain accepted")
		}

		if ctx.Err() != nil {
			t.Fatal("invalid configuration canceled the process")
		}
	}

	if err := ConfigureDrain(context.Background(), time.Second); err != nil {
		t.Fatalf("embedded command without signal host rejected: %v", err)
	}
}

func TestEssentialFailureFreezesBudgetWithoutChangingCallerCancellation(t *testing.T) {
	hard := make(chan int, 1)

	ctx, stop := signalContext(
		context.Background(),
		make(chan struct{}),
		20*time.Millisecond,
		func(code int) { hard <- code },
	)
	defer stop()

	boom := errors.New("owner failed")

	if err := lifecycle.RunEssential(
		ctx,
		lifecycle.Worker{
			Name:      "owner",
			Component: lifecycle.Func(func(context.Context) error { return boom }),
		},
	); !errors.Is(
		err,
		boom,
	) {
		t.Fatal(err)
	}

	if ctx.Err() != nil {
		t.Fatal("unexpected failure replaced the caller's error with cancellation")
	}

	if err := ConfigureDrain(ctx, time.Minute); !errors.Is(err, context.Canceled) {
		t.Fatalf("failure budget could be extended: %v", err)
	}

	select {
	case code := <-hard:
		if code != 130 {
			t.Fatal(code)
		}
	case <-time.After(time.Second):
		t.Fatal("essential failure did not start the hard deadline")
	}
}

func TestFailureDrainPreservesFirstAndSecondTerminationSignals(t *testing.T) {
	signals := make(chan struct{}, 2)
	hard := make(chan int, 1)

	ctx, stop := signalContext(
		context.Background(),
		signals,
		time.Minute,
		func(code int) { hard <- code },
	)
	defer stop()

	if err := lifecycle.RunEssential(
		ctx,
		lifecycle.Worker{
			Name:      "owner",
			Component: lifecycle.Func(func(context.Context) error { return nil }),
		},
	); err == nil {
		t.Fatal("essential nil exit accepted")
	}

	signals <- struct{}{}
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("first termination did not cancel")
	}

	select {
	case <-hard:
		t.Fatal("first termination was treated as a second signal")
	default:
	}

	signals <- struct{}{}
	select {
	case code := <-hard:
		if code != 130 {
			t.Fatal(code)
		}
	case <-time.After(time.Second):
		t.Fatal("second termination did not force a hard failure")
	}
}
