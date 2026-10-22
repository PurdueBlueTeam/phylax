// Package audit is the Linux kernel-audit telemetry module (design: "The
// agent -> Modules" proc and fim rows, "Telemetry sources"). It reads the
// audit netlink socket through go-libaudit, installs and guards its own rule
// set, reassembles multi-record events into process_start and file_change
// events, reports loss as telemetry_gap, and runs a throttled hash sweep of
// watched directories as the FIM source of truth.
//
// The implementation is Linux-only; on other platforms the package is empty.
package audit
