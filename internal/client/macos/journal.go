package macos

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"

	"github.com/StasOkhrym/homeharbor/internal/node/localstate"
	"github.com/StasOkhrym/homeharbor/internal/node/networkplan"
)

const journalVersion = 1

// journalState records intended ownership before each host mutation, so a
// process killed between a command and its response can still recover.
type journalState struct {
	Version         int                    `json:"version"`
	NetworkID       string                 `json:"network_id"`
	DeviceID        string                 `json:"device_id"`
	HighestRevision uint64                 `json:"highest_revision"`
	HighestHash     string                 `json:"highest_hash"`
	AppliedRevision uint64                 `json:"applied_revision"`
	Phase           string                 `json:"phase"`
	Interface       string                 `json:"interface,omitempty"`
	Routes          []netip.Prefix         `json:"routes,omitempty"`
	DNS             []networkplan.Resolver `json:"dns,omitempty"`
}

func loadJournal(store *localstate.Store, authority Authority) (journalState, error) {
	data, err := store.Read()
	if errors.Is(err, os.ErrNotExist) {
		return journalState{
			Version: journalVersion, NetworkID: authority.NetworkID, DeviceID: authority.DeviceID,
		}, nil
	}
	if err != nil {
		return journalState{}, err
	}

	var state journalState

	if err := json.Unmarshal(data, &state); err != nil {
		return journalState{}, err
	}

	if state.Version != journalVersion || state.NetworkID != authority.NetworkID ||
		state.DeviceID != authority.DeviceID {
		return journalState{}, errors.New("native ownership journal has different authority")
	}
	if state.Interface != "" && !utunName.MatchString(state.Interface) {
		return journalState{}, errors.New("native ownership journal has invalid interface")
	}

	return state, nil
}

func saveJournal(store *localstate.Store, state journalState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}

	return store.Replace(append(data, '\n'))
}

func readJournal(path string) (state journalState, result error) {
	store, err := localstate.Open(path)
	if err != nil {
		return journalState{}, err
	}
	defer func() { result = errors.Join(result, store.Close()) }()
	data, err := store.Read()
	if err != nil {
		return journalState{}, err
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return journalState{}, err
	}
	return state, nil
}
