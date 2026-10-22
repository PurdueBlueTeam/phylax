//go:build linux

package audit

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strconv"
)

// Process environment capture is deliberately narrow: an environment is full
// of secrets (tokens, passwords), so only the dynamic-loader injection family
// is ever stored, with its value, plus the control variables of the known
// libc interposer rootkit, recorded as presence markers only. Every other
// variable is discarded while parsing and never reaches an event.
const (
	environReadMax = 256 << 10 // bytes of /proc/<pid>/environ examined
	environValMax  = 512       // bytes kept of an allowed value
	environKeysMax = 8         // distinct captured keys per process
	envMarker      = "(set)"
)

var envValueKeys = map[string]bool{
	"LD_PRELOAD": true, "LD_AUDIT": true, "LD_LIBRARY_PATH": true,
	"LD_DEBUG": true, "LD_BIND_NOW": true, "LD_ASSUME_KERNEL": true,
}

// envMarkerKeys are recorded without their values.
var envMarkerKeys = map[string]bool{"HIDDEN": true, "BLOCKED": true}

// parseEnviron extracts the allowed variables from a NUL separated environ
// block. It is pure so it can be tested without /proc.
func parseEnviron(b []byte) map[string]any {
	var out map[string]any
	for len(b) > 0 && len(out) < environKeysMax {
		var ent []byte
		if i := bytes.IndexByte(b, 0); i >= 0 {
			ent, b = b[:i], b[i+1:]
		} else {
			ent, b = b, nil
		}
		k, v, ok := bytes.Cut(ent, []byte{'='})
		if !ok || len(k) > 32 {
			continue
		}
		key := string(k)
		switch {
		case envValueKeys[key]:
			if len(v) > environValMax {
				v = v[:environValMax]
			}
			if len(v) == 0 {
				continue
			}
			if out == nil {
				out = map[string]any{}
			}
			out[key] = string(v)
		case envMarkerKeys[key]:
			if out == nil {
				out = map[string]any{}
			}
			out[key] = envMarker
		}
	}
	return out
}

// readEnvKeys reads /proc/<pid>/environ (bounded) and returns the allowed
// variables, or nil. The caller must have established that pid is the process
// the event describes.
func readEnvKeys(procRoot string, pid int) map[string]any {
	f, err := os.Open(filepath.Join(procRoot, strconv.Itoa(pid), "environ"))
	if err != nil {
		return nil
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, environReadMax))
	return parseEnviron(b)
}
