package node

import "testing"

func TestParsePrefixListRejectsDefaultRoute(t *testing.T) {
	if _, err := ParsePrefixList("10.0.0.0/8,0.0.0.0/0"); err == nil {
		t.Fatal("default route was accepted")
	}
}
