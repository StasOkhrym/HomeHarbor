package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/StasOkhrym/homeharbor/internal/cli/host"
	"github.com/StasOkhrym/homeharbor/internal/node"
	"github.com/StasOkhrym/homeharbor/internal/node/localstate"
	"github.com/StasOkhrym/homeharbor/internal/platform/trust"
)

type enrollmentOptions struct {
	control, ca, state, name string
	timeout                  time.Duration
}

func newEnrollCommand() *cobra.Command {
	var options enrollmentOptions
	command := &cobra.Command{
		Use:   "enroll",
		Short: "Enroll a gateway without starting networking; emit only public identity JSON",
		Args:  host.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			return enrollGateway(command, options)
		},
	}
	flags := command.Flags()
	flags.StringVar(&options.control, "control", "", "trusted HTTPS control origin")
	flags.StringVar(&options.ca, "ca-file", "", "explicit trusted PEM CA file")
	flags.StringVar(&options.state, "state", "", "private gateway state file")
	flags.StringVar(&options.name, "name", "gateway", "gateway device name")
	flags.DurationVar(
		&options.timeout,
		"timeout",
		30*time.Second,
		"control enrollment deadline (up to 2 minutes)",
	)
	return command
}

func enrollGateway(command *cobra.Command, options enrollmentOptions) (result error) {
	if err := command.Context().Err(); err != nil {
		return err
	}
	origin, err := url.Parse(options.control)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil ||
		origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return errors.New("gateway enrollment requires an HTTPS control origin")
	}
	if options.ca == "" || options.state == "" || strings.TrimSpace(options.name) == "" ||
		options.timeout <= 0 || options.timeout > 2*time.Minute {
		return errors.New(
			"gateway enrollment requires CA, state, name and a positive deadline up to 2 minutes",
		)
	}
	client, err := trust.NewHTTPClientFromCAFile(options.ca)
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	store, err := localstate.Open(options.state)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, store.Close()) }()
	state, err := node.LoadOrCreateFrom(store)
	if err != nil {
		return err
	}
	if state.DeviceCredential == "" {
		scanner := bufio.NewScanner(command.InOrStdin())
		scanner.Buffer(make([]byte, 4096), 16*1024)
		token, err := host.ReadPrivateLine(scanner, command, "Gateway enrollment token")
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(command.Context(), options.timeout)
		defer cancel()
		if err := node.EnrollGateway(
			ctx,
			client,
			options.control,
			token,
			options.name,
			&state,
		); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := state.SaveTo(store); err != nil {
			return err
		}
	}
	if state.DeviceRole != "gateway" {
		return errors.New("existing state has no verified gateway role; refusing bootstrap export")
	}
	// Enrollment is finite. It never creates a WireGuard interface, starts a
	// relay/coordination worker or enables forwarding. The sandbox fence is
	// owned by its container entrypoint, separately from this command.
	return json.NewEncoder(command.OutOrStdout()).Encode(state.PublicIdentity())
}
