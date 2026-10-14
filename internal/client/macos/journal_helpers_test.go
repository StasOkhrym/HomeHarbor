package macos

import (
	"encoding/json"
	"errors"

	"github.com/StasOkhrym/homeharbor/internal/node/localstate"
)

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
