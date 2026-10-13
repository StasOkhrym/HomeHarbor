package macos

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

type installedHelper struct {
	sudoPath   string
	clientPath string
}

// NewInstalledHelper is side-effect free. Elevation occurs only for a verified
// apply or owned cleanup, using the explicitly installed fixed command.
func NewInstalledHelper() HelperExecutor {
	return installedHelper{sudoPath: "/usr/bin/sudo", clientPath: InstalledClientPath}
}

func (h installedHelper) Execute(ctx context.Context, request HelperRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	data, err := json.Marshal(request)
	if err != nil {
		return errors.New("encode native helper request")
	}
	if len(data) > MaxHelperRequestBytes {
		return errors.New("native helper request exceeds its size bound")
	}

	command := exec.CommandContext(ctx, h.sudoPath, "-n", "--", h.clientPath, "network-helper")
	command.Dir = "/"
	command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C"}
	command.Stdin = bytes.NewReader(data)
	command.WaitDelay = time.Second

	// Neither child output nor stdin enters errors/logging. An unexpectedly
	// changed executable must not be able to echo the caller's private key.
	if err := command.Run(); err != nil {
		return fmt.Errorf(
			"native helper failed; verify explicit installation and sudo access: %w",
			errors.Join(err, ctx.Err()),
		)
	}

	return nil
}
