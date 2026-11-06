// Package bench is the comms bench: the controller-side recorder that samples
// the agent-to-controller path every interval into a bounded JSONL file, the
// summary and envelope criteria over those records, and (in bench/load) the lab
// load generator built on the real agent runtime, link and spool. It imports
// only the standard library and is imported by the controller and cmd/phylax,
// never the other way round (design: "Testing and lab", "Comms bench"; plan:
// docs/impl/14-bench.md).
//
// ProcStats, the controller process CPU and RSS figure, is the only OS-specific
// piece: it reads /proc/self on Linux and reports 0, 0 elsewhere.
package bench
