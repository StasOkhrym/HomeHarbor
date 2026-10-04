//go:build darwin || linux || freebsd || openbsd || netbsd || dragonfly

package localstate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

func acquireLock(f *os.File) error { return unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) }
func openPrivate(parent *os.File, name string, create bool) (*os.File, error) {
	flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	if create {
		flags = unix.O_RDWR | unix.O_CREAT | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	}
	fd, err := unix.Openat(int(parent.Fd()), name, flags, 0600)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	file := os.NewFile(uintptr(fd), name)
	var stat unix.Stat_t
	err = unix.Fstat(fd, &stat)
	if err == nil && (stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1) {
		err = errors.New("state file has unsafe ownership or links")
	}
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	info, err := file.Stat()
	if err == nil && (!info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0) {
		err = errors.New("node state must be a private regular file")
	}
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}
func openParent(path string) (*os.File, error) {
	// Darwin exposes these fixed system aliases; canonicalize only those aliases.
	if runtime.GOOS == "darwin" {
		for _, alias := range []string{"/var", "/tmp"} {
			if path == alias || strings.HasPrefix(path, alias+"/") {
				path = "/private" + path
				break
			}
		}
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	current := os.NewFile(uintptr(fd), "/")
	for _, part := range strings.Split(strings.TrimPrefix(filepath.Clean(path), "/"), "/") {
		if part == "" {
			continue
		}
		next, err := unix.Openat(int(current.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(err, unix.ENOENT) {
			err = unix.Mkdirat(int(current.Fd()), part, 0700)
			if err == nil {
				err = current.Sync()
			}
			if err == nil || errors.Is(err, unix.EEXIST) {
				next, err = unix.Openat(int(current.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			}
		}
		if err != nil {
			_ = current.Close()
			return nil, fmt.Errorf("open state directory: %w", err)
		}
		child := os.NewFile(uintptr(next), filepath.Join(current.Name(), part))
		_ = current.Close()
		current = child
		var stat unix.Stat_t
		if err := unix.Fstat(int(current.Fd()), &stat); err != nil {
			_ = current.Close()
			return nil, err
		}
		if stat.Uid != 0 && stat.Uid != uint32(os.Geteuid()) {
			_ = current.Close()
			return nil, errors.New("state directory has unsafe ownership")
		}
		info, err := current.Stat()
		if err != nil {
			_ = current.Close()
			return nil, err
		}
		if info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0 {
			_ = current.Close()
			return nil, errors.New("state directory is writable by other users")
		}
	}
	info, err := current.Stat()
	if err != nil {
		_ = current.Close()
		return nil, err
	}
	if info.Mode().Perm()&0022 != 0 {
		_ = current.Close()
		return nil, errors.New("state parent must not be writable by other users")
	}
	return current, nil
}
func renameAt(parent *os.File, old, new string) error {
	return unix.Renameat(int(parent.Fd()), old, int(parent.Fd()), new)
}
func removeAt(parent *os.File, name string) error { return unix.Unlinkat(int(parent.Fd()), name, 0) }

func createTempAt(parent *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}
