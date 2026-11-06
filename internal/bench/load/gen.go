// Package load is the comms bench's lab load generator: a cut-able TCP proxy
// (proxy.go), a synthetic module and the real-agent runner (gen.go), and the
// scenario that cuts the link for a partition and checks the transport envelope
// against the controller's own bench file (run.go). It is lab-only: the load
// run writes synthetic events into the target controller's store, so
// phylax bench load requires -lab. It imports only internal/bench, internal/agent,
// internal/link, internal/spool and internal/event (plan: docs/impl/14-bench.md).
package load
