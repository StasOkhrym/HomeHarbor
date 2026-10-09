package node

// Role selects policy ownership; transport configuration is shared by both nodes.
type Role uint8

const (
	Client Role = iota
	Gateway
)
