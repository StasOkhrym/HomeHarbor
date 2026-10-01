// Package acceptance contains host-level network acceptance tests.
//
// The actual namespace tests are Linux-only because they exercise iproute2,
// nftables, and Linux network namespaces. They require the network_acceptance
// build tag so portable tests do not silently depend on root or system services.
package acceptance
