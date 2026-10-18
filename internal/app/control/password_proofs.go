package control

import (
	"time"

	redisclient "github.com/redis/go-redis/v9"

	identityredis "github.com/StasOkhrym/homeharbor/internal/control/identity/redis"
)

type passwordProofStores struct {
	login      *identityredis.Preauth
	enrollment *identityredis.Preauth
}

// The same bounded proof mechanics have separate authorities. A setup cookie
// can never select the normal login namespace, including across replicas.
func newPasswordProofStores(
	client redisclient.UniversalClient,
	prefix string,
	now func() time.Time,
	timeout time.Duration,
) (passwordProofStores, error) {
	login, err := identityredis.NewPreauth(client, prefix, now, timeout)
	if err != nil {
		return passwordProofStores{}, err
	}

	enrollment, err := identityredis.NewPreauth(client, prefix+":invited-enrollment", now, timeout)
	if err != nil {
		return passwordProofStores{}, err
	}

	return passwordProofStores{login: login, enrollment: enrollment}, nil
}
