package host

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
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
