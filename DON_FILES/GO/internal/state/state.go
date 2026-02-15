package state

import (
	"encoding/json"
	"os"
	"time"
)

type ReviewDecision string

const (
	DecisionGreen   ReviewDecision = "GREEN"
	DecisionRed     ReviewDecision = "RED"
	DecisionPending ReviewDecision = "PENDING"
)

type UserSyncState struct {
	UserID             string         `json:"userId,omitempty"`
	LastSeenRequestID  string         `json:"lastSeenRequestId,omitempty"`
	LastReviewDecision ReviewDecision `json:"lastReviewDecision,omitempty"`
	LastSyncAt         string         `json:"lastSyncAt,omitempty"`
}

type WorkflowState struct {
	LastIssueTokenBlock uint64                   `json:"lastIssueTokenBlock"`
	LastSyncBlock       uint64                   `json:"lastSyncBlock"`
	Users               map[string]UserSyncState `json:"users"`
}

func Default() WorkflowState {
	return WorkflowState{
		LastIssueTokenBlock: 0,
		LastSyncBlock:       0,
		Users:               map[string]UserSyncState{},
	}
}

func Read(path string) (WorkflowState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Default(), nil
		}
		return WorkflowState{}, err
	}

	st := Default()
	if err := json.Unmarshal(data, &st); err != nil {
		return Default(), nil
	}

	if st.Users == nil {
		st.Users = map[string]UserSyncState{}
	}

	return st, nil
}

func Write(path string, st WorkflowState) error {
	if st.Users == nil {
		st.Users = map[string]UserSyncState{}
	}

	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0o644)
}

func TouchSyncTime(u UserSyncState) UserSyncState {
	u.LastSyncAt = time.Now().UTC().Format(time.RFC3339)
	return u
}
