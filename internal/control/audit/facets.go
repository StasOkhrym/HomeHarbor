package audit

// Facets are bounded historical identity choices. Names are snapshots from the
// newest matching audit record, so deleted devices remain discoverable.
type Facet struct {
	ID   string
	Name string
}
type Facets struct {
	Actors  []Facet
	Devices []Facet
}
