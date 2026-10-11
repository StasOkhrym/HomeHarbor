package audit

const (
	DefaultQueryLimit = 100
	MaxQueryLimit     = 200
)

// RecordID is the database identity of a committed audit row. Event.ID is a
// separate optional delivery identity and may be empty for direct auth events.
type Record struct {
	RecordID int64 `json:"record_id"`
	Event    Event `json:"event"`
}

// Query asks for a bounded newest-first audit window or older history.
// BeforeID is exclusive; zero selects the most recent committed rows.
type Query struct {
	Limit    int
	BeforeID int64
	Action   string
	TargetID string
}
