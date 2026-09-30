//go:build !linux

// Package acceptance contains host-level network acceptance tests.
//
// The actual namespace tests are Linux-only because they exercise iproute2,
// nftables, and Linux network namespaces. This stub keeps the package visible
// to cross-platform Go commands without pretending those tests can run here.
package acceptance
