// Package node provides state fixtures for node and command tests.
package node

import (
	"errors"

	"github.com/StasOkhrym/homeharbor/internal/node"
	"github.com/StasOkhrym/homeharbor/internal/node/localstate"
)

// Save writes fixture state while releasing its short-lived owner on every path.
func Save(s node.State, path string) (err error) {
	store, err := localstate.Open(path)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, store.Close()) }()

	return s.SaveTo(store)
}

// LoadOrCreate never replaces corrupt or invalid state with a new identity.
func LoadOrCreate(path string) (state node.State, err error) {
	store, err := localstate.Open(path)
	if err != nil {
		return node.State{}, err
	}
	defer func() { err = errors.Join(err, store.Close()) }()

	return node.LoadOrCreateFrom(store)
}

func Load(path string) (state node.State, err error) {
	store, err := localstate.Open(path)
	if err != nil {
		return node.State{}, err
	}
	defer func() { err = errors.Join(err, store.Close()) }()

	return node.LoadFrom(store)
}
