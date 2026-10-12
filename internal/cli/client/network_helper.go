package client

import (
	"github.com/spf13/cobra"

	"github.com/StasOkhrym/homeharbor/internal/cli/host"
	"github.com/StasOkhrym/homeharbor/internal/client/macos"
)

func newNetworkHelperCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "network-helper",
		Short: "Apply bounded signed native network state from private stdin",
		Args:  host.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			return macos.RunSystemHelper(command.Context(), command.InOrStdin())
		},
	}
}
