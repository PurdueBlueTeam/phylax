package integrity

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
)

// Library flags.
const (
	FlagDeletedLibrary  = "deleted_library"
	FlagMemfdLibrary    = "memfd_library"
	FlagWritableLibrary = "writable_location" // mapped from /tmp, /dev/shm, /var/tmp, /home
)

// Mapping is one executable file-backed mapping.
type Mapping struct {
	Range   string // "start-end"
	Path    string
	Deleted bool
}

// ParseMaps extracts the distinct executable, file-backed mappings from the
// text of /proc/<pid>/maps. Anonymous mappings and pseudo-files ([heap],
// [vdso], /dev/*) are skipped; memfd and "(deleted)" mappings are kept.
func ParseMaps(r *bufio.Scanner) []Mapping {
	seen := map[string]bool{}
	var out []Mapping
	for r.Scan() {
		parts := strings.SplitN(r.Text(), " ", 6)
		if len(parts) < 6 {
			continue
		}
		perms, inode := parts[1], parts[4]
		path := strings.TrimLeft(parts[5], " ")
		if len(perms) < 3 || perms[2] != 'x' || inode == "0" || path == "" || !strings.HasPrefix(path, "/") {
			continue
		}
		if strings.HasPrefix(path, "/dev/") || strings.HasPrefix(path, "/SYSV") {
			continue
		}
		m := Mapping{Range: parts[0], Path: strings.TrimSuffix(path, " (deleted)"), Deleted: strings.HasSuffix(path, " (deleted)")}
		if k := m.Path + "|" + fmt.Sprint(m.Deleted); !seen[k] {
			seen[k] = true
			out = append(out, m)
		}
	}
	return out
}

// LibResult is the judgement of one mapped library.
type LibResult struct {
	Mapping
	Result Result
	Flags  []string
}

// CheckMaps checks every executable file-backed mapping of pid (the service
// binary itself, its libraries, LD_PRELOAD objects, PHP/Apache modules)
// against the ledger. Deleted mappings are read through
// /proc/<pid>/map_files when permitted. Alerting results emit events.
func (c *Checker) CheckMaps(ctx context.Context, pid int, cx Context) ([]LibResult, error) {
	f, err := os.Open(c.procPath(pid, "maps"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	maps := ParseMaps(sc)
	if err := sc.Err(); err != nil {
		return nil, err
	}
	cx.Trigger, cx.PID = TriggerLibrary, pid
	var out []LibResult
	for _, m := range maps {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		lr := LibResult{Mapping: m}
		if m.Deleted {
			lr.Flags = append(lr.Flags, FlagDeletedLibrary)
		}
		if strings.HasPrefix(m.Path, "/memfd:") {
			lr.Flags = append(lr.Flags, FlagMemfdLibrary)
		}
		for _, d := range []string{"/tmp/", "/dev/shm/", "/var/tmp/", "/home/"} {
			if strings.HasPrefix(m.Path, d) {
				lr.Flags = append(lr.Flags, FlagWritableLibrary)
			}
		}
		src := m.Path
		if m.Deleted || strings.HasPrefix(m.Path, "/memfd:") {
			src = c.procPath(pid, "map_files/"+m.Range)
		}
		file, oerr := os.Open(src)
		if oerr != nil {
			// Cannot read the content (no privilege, or gone): the finding is
			// still reportable by name.
			lr.Result = Result{Path: NormalizePath(m.Path), Verdict: Unknown, Note: "content unreadable: " + oerr.Error()}
		} else {
			h, herr := c.hashOpen(ctx, file, m.Path, false)
			file.Close()
			if herr != nil {
				lr.Result = Result{Path: NormalizePath(m.Path), Verdict: Unknown, Note: "hash failed: " + herr.Error()}
			} else {
				lr.Result = c.judge(ctx, m.Path, h)
			}
		}
		c.emit(lr.Result, cx, lr.Flags, map[string]any{"library": m.Path})
		out = append(out, lr)
	}
	return out, nil
}
