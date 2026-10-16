package storage

import (
	"context"

	"github.com/StasOkhrym/homeharbor/internal/control/audit"
)

// ListFacets reads only public audit identity snapshots. It never joins current
// device/account tables or loads unrelated dashboard resources.
func (s *Repository) ListFacets(ctx context.Context) (audit.Facets, error) {
	facets := audit.Facets{}

	rows, err := s.pool.Query(ctx, `WITH identities AS (
  SELECT id,'actor' AS kind,actor_id AS identity,metadata->>'actor_name' AS name FROM audit_events WHERE actor_type='admin' AND actor_id<>''
  UNION ALL
  SELECT id,'device',target_id,metadata->>'target_name' FROM audit_events WHERE target_type='device' AND target_id<>''
  UNION ALL
  SELECT id,'device',actor_id,metadata->>'actor_name' FROM audit_events WHERE actor_type='device' AND actor_id<>''
 ), latest AS (
  SELECT DISTINCT ON(kind,identity) id,kind,identity,name FROM identities ORDER BY kind,identity,id DESC
 ), bounded AS (
  (SELECT * FROM latest WHERE kind='actor' ORDER BY id DESC LIMIT 200)
  UNION ALL
  (SELECT * FROM latest WHERE kind='device' ORDER BY id DESC LIMIT 200)
 ) SELECT kind,identity,COALESCE(name,'') FROM bounded ORDER BY kind,id DESC`)
	if err != nil {
		return facets, err
	}
	defer rows.Close()

	for rows.Next() {
		var kind string
		var facet audit.Facet

		if err := rows.Scan(&kind, &facet.ID, &facet.Name); err != nil {
			return audit.Facets{}, err
		}

		if !audit.PublicText(facet.Name, 128) {
			facet.Name = facet.ID
		}

		if kind == "actor" {
			facets.Actors = append(facets.Actors, facet)
		} else {
			facets.Devices = append(facets.Devices, facet)
		}
	}

	return facets, rows.Err()
}
