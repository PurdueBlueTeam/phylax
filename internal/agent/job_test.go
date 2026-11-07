package agent

import "testing"

func TestDefaultJobLimits(t *testing.T) {
	if got, want := DefaultJobLimits(0).MemoryBytes, uint64((80+64)<<20); got != want {
		t.Errorf("DefaultJobLimits(0).MemoryBytes = %d, want %d", got, want)
	}
	if got, want := DefaultJobLimits(256).MemoryBytes, uint64((80+256+64)<<20); got != want {
		t.Errorf("DefaultJobLimits(256).MemoryBytes = %d, want %d", got, want)
	}
	if got := DefaultJobLimits(0).CPUPercent; got != 50 {
		t.Errorf("DefaultJobLimits(0).CPUPercent = %d, want 50", got)
	}
}

func TestMemoryLimitBytes(t *testing.T) {
	if got, want := MemoryLimitBytes(0), int64(80<<20); got != want {
		t.Errorf("MemoryLimitBytes(0) = %d, want %d", got, want)
	}
	if got, want := MemoryLimitBytes(512), int64((80+512)<<20); got != want {
		t.Errorf("MemoryLimitBytes(512) = %d, want %d", got, want)
	}
	if got, want := MemoryLimitBytes(-1), int64(80<<20); got != want {
		t.Errorf("MemoryLimitBytes(-1) = %d, want %d", got, want)
	}
}
