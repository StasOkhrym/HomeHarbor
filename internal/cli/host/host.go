// Package host owns command execution and process exit classification.
package host

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
)

type usageError struct{ cause error }

func (e usageError) Error() string { return e.cause.Error() }
func (e usageError) Unwrap() error { return e.cause }

// NoArgs marks unexpected positional arguments as a command usage error.
func NoArgs(cmd *cobra.Command, args []string) error {
	if err := cobra.NoArgs(cmd, args); err != nil {
		return usageError{cause: err}
	}

	return nil
}

// ExactArgs marks an incorrect positional argument count as a usage error.
func ExactArgs(count int) cobra.PositionalArgs {
	check := cobra.ExactArgs(count)
	return func(cmd *cobra.Command, args []string) error {
		if err := check(cmd, args); err != nil {
			return usageError{cause: err}
		}

		return nil
	}
}

// Execute routes all output through the supplied streams and never exits the
// process. Command constructors must return fresh trees for repeated calls.
func Execute(
	ctx context.Context,
	args []string,
	stdout, stderr io.Writer,
	root *cobra.Command,
) int {
	if ctx == nil {
		ctx = context.Background()
	}
	if root == nil {
		_, _ = fmt.Fprintln(stderr, "command is required")
		return 1
	}
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SilenceErrors = true
	root.SilenceUsage = true
	if root.Version == "" {
		root.Version = "dev"
	}
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return usageError{cause: err}
	})
	err := root.ExecuteContext(ctx)
	if err == nil {
		return 0
	}
	_, _ = fmt.Fprintln(stderr, err)
	if errors.Is(err, context.Canceled) {
		return 130
	}
	var usage usageError
	if errors.As(err, &usage) || strings.HasPrefix(err.Error(), "unknown command ") {
		return 2
	}
	return 1
}
