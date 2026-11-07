package agent

// JobLimits are the Windows Job Object caps on the agent process.
type JobLimits struct {
	MemoryBytes uint64
	// CPUPercent is 0 (no CPU cap) or 1..100: a hard cap of that share of one
	// core, matching systemd's --cpu-quota percentage.
	CPUPercent int
}

const (
	// BaseMemoryMB is the agent's own footprint; a module's held memory is
	// counted on top of it.
	BaseMemoryMB = 80
	// JobHeadroomMB keeps the soft Go limit below the hard Job Object cap.
	JobHeadroomMB = 64
)

// DefaultJobLimits is the 80 MB base plus the capture module's configured held
// budget plus 64 MB headroom, and a 50% CPU cap (design: the process hard cap;
// the capture ring and freeze hold are Go heap on top of the base).
func DefaultJobLimits(heldMB int64) JobLimits {
	if heldMB < 0 {
		heldMB = 0
	}
	return JobLimits{MemoryBytes: uint64(BaseMemoryMB+heldMB+JobHeadroomMB) << 20, CPUPercent: 50}
}

// MemoryLimitBytes is the soft Go memory limit for a held budget: the 80 MB
// base plus the held bytes, which is JobHeadroomMB below DefaultJobLimits.
func MemoryLimitBytes(heldMB int64) int64 {
	if heldMB < 0 {
		heldMB = 0
	}
	return int64(BaseMemoryMB+heldMB) << 20
}
