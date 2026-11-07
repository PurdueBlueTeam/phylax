//go:build !windows

package agent

// ApplyJobLimits is a no-op outside Windows: systemd's MemoryMax and CPUQuota
// are the hard caps there.
func ApplyJobLimits(JobLimits) error { return nil }
