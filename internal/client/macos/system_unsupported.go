//go:build !darwin && !linux

package macos

import (
	"context"
	"errors"
	"io"
)

func RunSystemHelper(context.Context, io.Reader) error {
	return errors.New("native network-helper is only available on macOS")
}
