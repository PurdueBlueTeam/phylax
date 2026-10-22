//go:build linux

package integrity

import (
	"bufio"
	"context"
	"io"
	"os"
	"strconv"
	"strings"
)

const (
	maxRegionBytes  = 64 << 20
	maxProcessBytes = 512 << 20
)

// ScanProcess scans the readable memory regions of pid through
// /proc/<pid>/mem (the agent reads memory, not the engine). Regions are
// scanned separately, so a pattern straddling two regions is not found.
// Needs ptrace-level privilege for other users' processes.
func (g GoScanner) ScanProcess(ctx context.Context, pid int) ([]RuleMatch, error) {
	mf, err := os.Open("/proc/" + strconv.Itoa(pid) + "/maps")
	if err != nil {
		return nil, err
	}
	defer mf.Close()
	mem, err := os.Open("/proc/" + strconv.Itoa(pid) + "/mem")
	if err != nil {
		return nil, err
	}
	defer mem.Close()
	var total int64
	agg := map[string]*RuleMatch{}
	var order []string
	sc := bufio.NewScanner(mf)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), " ", 6)
		if len(parts) < 5 || len(parts[1]) < 1 || parts[1][0] != 'r' {
			continue
		}
		if len(parts) == 6 {
			if n := strings.TrimSpace(parts[5]); n == "[vvar]" || n == "[vsyscall]" || n == "[vvar_vclock]" || strings.HasPrefix(n, "/dev/") {
				continue
			}
		}
		lo, hi, ok := strings.Cut(parts[0], "-")
		if !ok {
			continue
		}
		a, err1 := strconv.ParseUint(lo, 16, 64)
		b, err2 := strconv.ParseUint(hi, 16, 64)
		if err1 != nil || err2 != nil || b <= a {
			continue
		}
		size := int64(b - a)
		if size > maxRegionBytes {
			size = maxRegionBytes
		}
		if total += size; total > maxProcessBytes {
			break
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ms, err := g.M.ScanReader(ctx, "", io.NewSectionReader(mem, int64(a), size))
		if err != nil {
			continue // unreadable region (EIO), skip
		}
		for _, m := range ms {
			if e, ok := agg[m.Rule]; ok {
				e.Strings = append(e.Strings, m.Strings...)
			} else {
				mm := m
				agg[m.Rule] = &mm
				order = append(order, m.Rule)
			}
		}
	}
	var out []RuleMatch
	for _, k := range order {
		out = append(out, *agg[k])
	}
	if sc.Err() != nil {
		return out, sc.Err()
	}
	return out, nil
}
