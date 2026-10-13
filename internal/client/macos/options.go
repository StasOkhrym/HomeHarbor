package macos

import (
	"errors"
	"net/netip"

	"github.com/StasOkhrym/homeharbor/internal/node/networkplan"
)

func ParseBounds(overlay, private, suffix string) (networkplan.Bounds, error) {
	overlayPrefix, overlayErr := netip.ParsePrefix(overlay)

	privatePrefix, privateErr := netip.ParsePrefix(private)
	bounds := networkplan.Bounds{Overlay: overlayPrefix, Private: privatePrefix, Suffix: suffix}
	if overlayErr != nil || privateErr != nil || !validNativeBounds(bounds) {
		return networkplan.Bounds{}, errors.New(
			"native network bounds must be disjoint private prefixes and a safe DNS suffix",
		)
	}

	return bounds, nil
}
