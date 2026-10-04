//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd && !dragonfly

package localstate

import (
	"errors"
	"os"
)

var errUnsupported = errors.New("single-owner state locking is unsupported on this platform")

func acquireLock(*os.File) error                           { return errUnsupported }
func openParent(string) (*os.File, error)                  { return nil, errUnsupported }
func openPrivate(*os.File, string, bool) (*os.File, error) { return nil, errUnsupported }
func renameAt(*os.File, string, string) error              { return errUnsupported }
func removeAt(*os.File, string) error                      { return errUnsupported }

func createTempAt(*os.File, string) (*os.File, error) { return nil, errUnsupported }
