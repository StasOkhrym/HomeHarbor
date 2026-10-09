// Package control adapts the control-plane runtime to the shared CLI host.
package control

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"

	controlapp "github.com/StasOkhrym/homeharbor/internal/app/control"
	"github.com/StasOkhrym/homeharbor/internal/cli/host"
	"github.com/StasOkhrym/homeharbor/internal/platform/config"
)

type runner func(context.Context, config.Control, *slog.Logger) error

// NewCommand constructs a fresh command without loading configuration or
// acquiring any control-plane resources.
func NewCommand() *cobra.Command { return newCommand(runControl) }

func newCommand(run runner) *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "control",
		Short: "Run the HomeHarbor control plane",
		Args:  host.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if err := ctx.Err(); err != nil {
				return err
			}

			logger := slog.New(slog.NewJSONHandler(cmd.OutOrStdout(), nil))

			cfg, err := config.LoadControl(config.Sources{File: configPath})
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}

			if err := ctx.Err(); err != nil {
				return err
			}

			if err := run(ctx, cfg, logger); err != nil {
				return fmt.Errorf("run control: %w", err)
			}

			return ctx.Err()
		},
	}
	cmd.Flags().StringVar(
		&configPath, "config", "config/control.toml", "control configuration path",
	)
	return cmd
}

func runControl(ctx context.Context, cfg config.Control, logger *slog.Logger) error {
	app, err := controlapp.New(ctx, cfg, logger)
	if err != nil {
		return fmt.Errorf("create control runtime: %w", err)
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	logger.Info("control listening", "address", cfg.Server.ListenAddress)

	if err := app.Run(ctx); err != nil {
		return fmt.Errorf("serve control: %w", err)
	}

	return ctx.Err()
}
