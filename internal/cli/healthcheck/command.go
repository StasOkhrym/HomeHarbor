// Package healthcheck adapts the container readiness probe to the shared CLI.
package healthcheck

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/spf13/cobra"

	"github.com/StasOkhrym/homeharbor/internal/cli/host"
)

const probeTimeout = 2 * time.Second

// NewCommand constructs a probe without making any network request.
func NewCommand() *cobra.Command {
	return newCommand(&http.Client{Timeout: probeTimeout})
}

func newCommand(client *http.Client) *cobra.Command {
	return &cobra.Command{
		Use:   "healthcheck URL",
		Short: "Check a HomeHarbor HTTP health endpoint",
		Args:  host.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := cmd.Context().Err(); err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), probeTimeout)
			defer cancel()

			request, err := http.NewRequestWithContext(ctx, http.MethodGet, args[0], nil)
			if err != nil {
				return err
			}

			response, err := client.Do(request)
			if err != nil {
				return err
			}
			defer func() { _ = response.Body.Close() }()

			if response.StatusCode < http.StatusOK ||
				response.StatusCode >= http.StatusMultipleChoices {
				return errors.New(response.Status)
			}

			return nil
		},
	}
}
