package client

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/StasOkhrym/homeharbor/internal/cli/host"
	"github.com/StasOkhrym/homeharbor/internal/client/macos"
	"github.com/StasOkhrym/homeharbor/internal/node"
	"github.com/StasOkhrym/homeharbor/internal/node/localstate"
	"github.com/StasOkhrym/homeharbor/internal/platform/config"
)

func newNetworkCloseCommand(helper macos.HelperExecutor, platform string) *cobra.Command {
	var path string
	command := &cobra.Command{
		Use:   "network-close",
		Short: "Recover owned macOS networking using existing client state",
		Args:  host.NoArgs,
		RunE: func(command *cobra.Command, _ []string) (result error) {
			if err := command.Context().Err(); err != nil {
				return err
			}

			if platform != "darwin" {
				return errors.New("network-close is only available on macOS")
			}
			if path == "" {
				return errors.New("network-close requires --config with native client ownership")
			}

			cfg, err := config.LoadClient(config.Sources{File: path})
			if err != nil {
				return err
			}
			if !cfg.Native.Enabled || cfg.Identity.StatePath == "" ||
				cfg.Coordination.NetworkID == "" ||
				cfg.Coordination.RootPublicKeyFile == "" {
				return errors.New(
					"network-close requires native state, network ID and signing root",
				)
			}

			root, err := node.LoadPublicKeyFile(cfg.Coordination.RootPublicKeyFile)
			if err != nil {
				return err
			}

			info, err := os.Lstat(cfg.Identity.StatePath)
			if err != nil {
				return fmt.Errorf("load existing client identity: %w", err)
			}
			if !info.Mode().IsRegular() {
				return errors.New("recovery state must be an existing regular file")
			}

			store, err := localstate.Open(cfg.Identity.StatePath)
			if err != nil {
				return err
			}
			defer func() { result = errors.Join(result, store.Close()) }()

			state, err := node.LoadFrom(store)
			if err != nil {
				return err
			}
			if state.DeviceID == "" {
				return errors.New("native cleanup requires an already joined client identity")
			}

			if err := macos.CloseOwned(command.Context(), macos.Authority{
				Root: root, NetworkID: cfg.Coordination.NetworkID, DeviceID: state.DeviceID,
			}, cfg.Runtime.OperationTimeout, helper); err != nil {
				return err
			}

			_, err = fmt.Fprintln(command.OutOrStdout(), "Owned native networking closed.")

			return err
		},
	}
	command.Flags().StringVar(&path, "config", "", "native client TOML configuration")
	return command
}
