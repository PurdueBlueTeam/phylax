package chains

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/store"
	"github.com/PurdueBlueTeam/phylax/internal/traceback"
)

// AddRemediation generates the per-hop remediation items: close the entry,
// remove the persistence, rotate the credential that was used, block the
// source. The same action is listed once, on the earliest hop that needs it.
func AddRemediation(c *Chain) {
	seen := map[string]bool{}
	add := func(h *Hop, k ItemKind, host, target, text string) {
		key := string(k) + "|" + host + "|" + target
		if seen[key] || target == "" {
			return
		}
		seen[key] = true
		h.Items = append(h.Items, Item{Kind: k, Host: host, Target: target, Text: text, State: StateOpen})
	}
	for i := range c.Hops {
		h := &c.Hops[i]
		h.Items = nil
		switch h.Kind {
		case Access:
			svc := orStr(h.Service, "the exposed service")
			if h.Account != "" {
				add(h, CloseEntry, h.DstHost, "entry:"+h.DstHost+":"+svc,
					fmt.Sprintf("Close the entry: remove the default or weak credential and restrict %s logins on %s (key-only or allow-list)", svc, h.DstHost))
				add(h, RotateCredential, h.DstHost, h.Account, fmt.Sprintf("Rotate the credential for %s (used from %s)", h.Account, h.SrcAddr))
			} else {
				add(h, CloseEntry, h.DstHost, "entry:"+h.DstHost+":"+svc,
					fmt.Sprintf("Close the entry: patch or disable the exploited %s function on %s", svc, h.DstHost))
			}
			if h.SrcAddr != "" && !traceback.IsPrivate(h.SrcAddr) && !traceback.IsLoopback(h.SrcAddr) {
				add(h, BlockSource, "", h.SrcAddr, fmt.Sprintf("Block %s at the perimeter", h.SrcAddr))
			}
		case Move:
			svc := orStr(h.Service, "remote service")
			add(h, CloseEntry, h.DstHost, fmt.Sprintf("path:%s>%s:%s", h.SrcHost, h.DstHost, svc),
				fmt.Sprintf("Close the path: restrict %s from %s to %s to the hosts that need it", svc, orStr(h.SrcHost, h.SrcAddr), orStr(h.DstHost, h.DstAddr)))
			if h.Account != "" {
				add(h, RotateCredential, h.DstHost, h.Account, fmt.Sprintf("Rotate the credential for %s (used to reach %s)", h.Account, orStr(h.DstHost, h.DstAddr)))
			}
		case Exec:
			if h.Proc != nil && implantPath(h.Proc.Exe) {
				add(h, RemoveArtifact, h.DstHost, h.Proc.Exe, fmt.Sprintf("Remove %s on %s, confirm it does not respawn, and hash-check the host", h.Proc.Exe, h.DstHost))
			}
		case Change:
			switch {
			case strings.HasPrefix(h.Path, "account:"):
				add(h, RemovePersistence, h.DstHost, h.Path, fmt.Sprintf("Delete the account %s created on %s", strings.TrimPrefix(h.Path, "account:"), h.DstHost))
			case strings.HasPrefix(h.Path, "group:"):
				add(h, RemovePersistence, h.DstHost, h.Path, fmt.Sprintf("Remove %s from the group", strings.ReplaceAll(strings.TrimPrefix(h.Path, "group:"), "+", ": ")))
			case h.Path == "dcsync":
				add(h, RotateCredential, h.DstHost, "krbtgt", "Credential replication was used: reset krbtgt twice and rotate every privileged credential")
			case h.Persistence:
				add(h, RemovePersistence, h.DstHost, h.Path, fmt.Sprintf("Remove the persistence %s on %s and re-hunt the host", h.Path, h.DstHost))
			default:
				add(h, RemoveArtifact, h.DstHost, h.Path, fmt.Sprintf("Remove or restore %s on %s from the known-good backup", h.Path, h.DstHost))
			}
		case Egress:
			add(h, BlockSource, "", h.DstAddr, fmt.Sprintf("Block egress to %s:%d (command-and-control or exfiltration destination)", h.DstAddr, h.DstPort))
		}
	}
}

func implantPath(p string) bool {
	l := strings.ToLower(strings.ReplaceAll(p, `\`, "/"))
	for _, s := range []string{"/tmp/", "/dev/shm/", "/var/tmp/", "/home/", "/appdata/", "/temp/", "/users/public/", "/programdata/"} {
		if strings.Contains(l, s) {
			return true
		}
	}
	return false
}

// Verify checks open and applied items against later telemetry and marks the
// ones it can prove closed as verified:
//
//   - rotate_credential: a password reset of the account after the hop
//     (krbtgt needs two resets);
//   - remove_persistence and remove_artifact: a later delete of the same path
//     on the same host, a group removal, or a scheduled-task deletion.
//
// close_entry and block_source cannot be proven from events and stay for the
// operator to mark. It returns how many items changed.
func (b *Builder) Verify(ctx context.Context, c *Chain) (int, error) {
	agents, err := b.Src.Agents(ctx)
	if err != nil {
		return 0, err
	}
	var from time.Time
	for _, h := range c.Hops {
		if from.IsZero() || h.Start.Before(from) {
			from = h.Start
		}
	}
	var secs, files []traceback.Obs
	for _, a := range agents {
		off := b.Cfg.off(a.ID)
		for _, k := range []string{traceback.KindSecEvent, traceback.KindFileChange} {
			evs, err := b.Src.Events(ctx, store.Query{Agent: a.ID, Kind: k, From: from.Add(off), Limit: store.MaxQueryLimit})
			if err != nil {
				return 0, err
			}
			for _, e := range evs {
				o := traceback.Normalize(e, off)
				if k == traceback.KindSecEvent {
					secs = append(secs, o)
				} else {
					files = append(files, o)
				}
			}
		}
	}
	changed := 0
	for i := range c.Hops {
		h := &c.Hops[i]
		for j := range h.Items {
			it := &h.Items[j]
			if it.State == StateVerified {
				continue
			}
			note := verifyItem(*h, *it, secs, files)
			if note != "" {
				it.State, it.Note = StateVerified, note
				changed++
			}
		}
	}
	return changed, nil
}

func verifyItem(h Hop, it Item, secs, files []traceback.Obs) string {
	after := func(o traceback.Obs) bool { return o.T.After(h.End) }
	switch it.Kind {
	case RotateCredential:
		need, n := 1, 0
		var last traceback.Obs
		if it.Target == "krbtgt" {
			need = 2
		}
		for _, o := range secs {
			if o.Category == "account_change" && o.Op == "password_reset" && o.Account == traceback.NormAccount(it.Target) && after(o) {
				n++
				last = o
			}
		}
		if n >= need {
			return fmt.Sprintf("password of %s reset at %s on %s", it.Target, last.T.UTC().Format(time.RFC3339), last.Host)
		}
	case RemovePersistence, RemoveArtifact:
		switch {
		case strings.HasPrefix(it.Target, "group:"):
			member := it.Target[strings.LastIndex(it.Target, "+")+1:]
			for _, o := range secs {
				if o.Category == "group_change" && o.Op == "member_removed" && traceback.NormAccount(fmt.Sprint(o.Ev.Fields["member_name"])) == traceback.NormAccount(member) && after(o) {
					return fmt.Sprintf("%s removed from the group at %s", member, o.T.UTC().Format(time.RFC3339))
				}
			}
		case strings.HasPrefix(it.Target, "task:"):
			name := strings.TrimPrefix(it.Target, "task:")
			for _, o := range secs {
				if o.Category == "scheduled_task" && o.Op == "deleted" && o.Host == it.Host && after(o) && (name == "" || strings.Contains(secTarget(o), name)) {
					return "scheduled task deleted at " + o.T.UTC().Format(time.RFC3339)
				}
			}
		default:
			for _, o := range files {
				if o.Host == it.Host && o.Path == it.Target && after(o) && (o.Op == "delete" || o.Op == "remove" || o.Op == "unlink") {
					return "file deleted at " + o.T.UTC().Format(time.RFC3339)
				}
			}
		}
	}
	return ""
}
