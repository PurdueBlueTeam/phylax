package bench

import (
	"runtime"
	"testing"
	"time"
)

func TestProcStats(t *testing.T) {
	t.Skip("unimplemented: W14 Task 7")
	if runtime.GOOS != "linux" {
		t.Skip("needs /proc")
	}
	c0, r0 := ProcStats()
	end := time.Now().Add(300 * time.Millisecond)
	for x := 0; time.Now().Before(end); x++ {
		_ = x * x
	}
	c1, _ := ProcStats()
	if c1-c0 < 100 || r0 < 1<<20 {
		t.Fatalf("cpu %d -> %d rss %d", c0, c1, r0)
	}
}
