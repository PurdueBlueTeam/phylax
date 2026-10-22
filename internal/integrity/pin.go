package integrity

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Pin ties a scored service to its process and its on-disk binary.
type Pin struct {
	Service string
	PID     int
	Path    string // the binary the service is supposed to run
	Process string // process-tree pointer for evidence
}

// Pin flags.
const (
	FlagImageDeleted     = "image_deleted"             // running image's file was unlinked ("(deleted)")
	FlagInodeReplaced    = "inode_replaced"            // file at Path is not the inode the process runs
	FlagDiskDiffers      = "disk_differs_from_running" // hash on disk != hash of running image
	FlagMemfdImage       = "memfd_image"
	FlagDiskMissing      = "disk_missing"
	FlagStaleAfterUpdate = "stale_after_update" // both images are ledger-good: update pending restart
)

// PinResult is the outcome of verifying a pin.
type PinResult struct {
	Pin
	Running Result
	Disk    *Result // nil if the file is missing
	Flags   []string
	Verdict Verdict // worst of Running and Disk
}

// ErrProcessGone means the pinned process no longer exists.
var ErrProcessGone = errors.New("integrity: pinned process is gone")

// CheckPin compares the running image (/proc/<pid>/exe, opened through the
// magic link so it is the real inode even when "(deleted)") against the file
// on disk and the ledger. It catches "swapped but not yet restarted" (running
// image good or deleted, disk trojaned) and "restarted on the trojan"
// (running image bad). It emits integrity.verdict when anything is wrong.
func (c *Checker) CheckPin(ctx context.Context, p Pin) (PinResult, error) {
	res := PinResult{Pin: p}
	pe := c.procPath(p.PID, "exe")
	tgt, err := os.Readlink(pe)
	if err != nil {
		return res, fmt.Errorf("%w: pid %d: %v", ErrProcessGone, p.PID, err)
	}
	if strings.HasSuffix(tgt, " (deleted)") {
		res.Flags = append(res.Flags, FlagImageDeleted)
	}
	if strings.HasPrefix(tgt, "/memfd:") {
		res.Flags = append(res.Flags, FlagMemfdImage)
	}
	rf, err := os.Open(pe)
	if err != nil {
		return res, err
	}
	defer rf.Close()
	rh, err := c.hashOpen(ctx, rf, p.Path, false)
	if err != nil {
		return res, err
	}
	res.Running = c.judge(ctx, p.Path, rh)
	res.Verdict = res.Running.Verdict

	df, derr := os.Open(p.Path)
	if derr != nil {
		res.Flags = append(res.Flags, FlagDiskMissing)
	} else {
		defer df.Close()
		dh, err := c.hashOpen(ctx, df, p.Path, false)
		if err != nil {
			return res, err
		}
		dr := c.judge(ctx, p.Path, dh)
		res.Disk = &dr
		res.Verdict = Worse(res.Verdict, dr.Verdict)
		if dh.ID.Dev != rh.ID.Dev || dh.ID.Ino != rh.ID.Ino || dh.ID.Path != rh.ID.Path {
			res.Flags = append(res.Flags, FlagInodeReplaced)
		}
		if dh.Sum != rh.Sum {
			res.Flags = append(res.Flags, FlagDiskDiffers)
		}
	}
	for _, r := range []*Result{&res.Running, res.Disk} {
		if r != nil && r.Verdict.Alerting() {
			prefix := "running_"
			if r == res.Disk {
				prefix = "disk_"
			}
			res.Flags = append(res.Flags, prefix+string(r.Verdict))
		}
	}
	if !res.Verdict.Alerting() && len(res.Flags) > 0 && !has(res.Flags, FlagMemfdImage) && !has(res.Flags, FlagDiskMissing) {
		// Both images are ledger-good (e.g. a package update awaiting a
		// restart): informational, not an attack.
		res.Flags = append(res.Flags, FlagStaleAfterUpdate)
	}
	extra := map[string]any{"running_sha256": res.Running.SHA256.String(), "running_verdict": string(res.Running.Verdict), "running_target": tgt}
	ev := res.Running
	if res.Disk != nil {
		extra["disk_sha256"] = res.Disk.SHA256.String()
		extra["disk_verdict"] = string(res.Disk.Verdict)
		if !res.Running.Verdict.Alerting() && res.Disk.Verdict.Alerting() {
			ev = *res.Disk // report the trojaned file as the primary evidence
		}
	}
	ev.Verdict = res.Verdict
	c.emit(ev, Context{Trigger: TriggerPin, PID: p.PID, UID: -1, Process: p.Process, Service: p.Service, Pinned: true}, res.Flags, extra)
	return res, nil
}

func has(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
