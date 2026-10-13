package nodecmd

import (
	"encoding/json"
	"errors"
	"os"

	"github.com/spf13/cobra"

	"github.com/StasOkhrym/homeharbor/internal/cli/host"
	"github.com/StasOkhrym/homeharbor/internal/node"
	"github.com/StasOkhrym/homeharbor/internal/node/localstate"
)

func newIdentityCommand() *cobra.Command {
	var path string
	command := &cobra.Command{
		Use:   "identity",
		Short: "Read an existing joined node's public identity without control access",
		Args:  host.NoArgs,
		RunE: func(command *cobra.Command, _ []string) (result error) {
			if err := command.Context().Err(); err != nil {
				return err
			}

			if path == "" {
				return errors.New("identity requires --state")
			}

			info, err := os.Lstat(path)
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return errors.New("identity requires an existing regular state file")
			}

			store, err := localstate.Open(path)
			if err != nil {
				return err
			}
			defer func() { result = errors.Join(result, store.Close()) }()

			state, err := node.LoadFrom(store)
			if err != nil {
				return err
			}
			if state.DeviceID == "" {
				return errors.New("identity requires an already joined node")
			}

			return json.NewEncoder(command.OutOrStdout()).Encode(state.PublicIdentity())
		},
	}
	command.Flags().StringVar(&path, "state", "", "existing private node state file")
	return command
}
