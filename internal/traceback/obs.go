// Package traceback walks a change back to its cause (design: "Traffic
// labeling, change detection and trace-back"): the writer process, its
// lineage, the inbound connection it was serving, the source of that
// connection and everything else the source did, with a confidence for every
// link and an explicit reason wherever the chain breaks. It reads only stored
// events; it never guesses silently.
package traceback

import (
	"encoding/json"
	"net/netip"
	"strconv"
	"strings"
	"time"

	netmod "github.com/PurdueBlueTeam/phylax/internal/collect/net"
	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// Event kinds this package understands (produced by the audit, net and winevt
// collectors).
const (
	KindProcessStart = "process_start"
	KindFileChange   = "file_change"
	KindConnOpened   = "net.connection_opened"
	KindConnClosed   = "net.connection_closed"
	KindEgressDenied = "net.egress_denied"
	KindNetConnect   = "net_connect" // audit connect/accept and Sysmon 3
	KindAuthSuccess  = "auth_success"
	KindAuthFail     = "auth_fail"
	KindSecEvent     = "sec_event"
)

// Class is the normalised role of an event.
type Class int

const (
	ClassOther Class = iota
	ClassProc
	ClassFile
	ClassConnOpen
	ClassConnClose
	ClassAuthOK
	ClassAuthFail
	ClassSec
	ClassEgressDenied
)

// Obs is an event reduced to the fields trace-back and chain building use.
// Linux audit, the net module and Windows (Sysmon, Security) report the same
// facts under different names; Normalize hides that.
type Obs struct {
	Ev    event.Event
	Host  string    // agent id
	T     time.Time // event time with the agent's clock offset removed
	Class Class

	// Process (ClassProc; also the writer of a ClassFile, and the owner of a
	// connection).
	PID, PPID  int64
	StartTicks uint64
	Exe, Comm  string
	Cmdline    string
	PExe       string
	SHA256     string
	User       string // normalised account the process ran as, when known

	// File change.
	Path, Op string
	Sweep    bool // found by the hash sweep: no writer known

	// Connection (ClassConnOpen/Close/EgressDenied).
	Dir          string // "in" or "out"
	LAddr, RAddr string
	LPort, RPort int
	Proto        string
	Service      string
	CID          string

	// Authentication and Security events.
	Account    string // normalised: who logged in / the target account of a change
	Actor      string // normalised: who performed it (Security subject account)
	Source     string // remote address
	SourcePort int
	LogonType  int
	Category   string // sec_event category
	Method     string

	Tag string // plan tag: our own activity
}

// Ref points at a stored event.
type Ref struct {
	Agent string `json:"agent"`
	Seq   uint64 `json:"seq"`
}

// Ref returns the evidence pointer for o.
func (o Obs) Ref() Ref { return Ref{o.Ev.Agent, o.Ev.Seq} }

// Str returns a top-level string field of the underlying event.
func (o Obs) Str(k string) string { return str(o.Ev.Fields, k) }

// Normalize reduces ev. offset is the agent's clock minus the controller's
// (zero when unknown); it is subtracted from the event time.
func Normalize(ev event.Event, offset time.Duration) Obs {
	f := ev.Fields
	o := Obs{Ev: ev, Host: ev.Agent, T: ev.Time.Add(-offset), Tag: str(f, "tag")}
	switch ev.Kind {
	case KindProcessStart:
		o.Class = ClassProc
		o.PID, o.PPID = num(f, "pid"), num(f, "ppid")
		o.StartTicks = uint64(num(f, "start_ticks"))
		o.Exe = first(str(f, "exe"), str(f, "image"))
		o.Comm = str(f, "comm")
		o.Cmdline = str(f, "cmdline")
		o.PExe = first(str(f, "pexe"), nestedStr(f, "parent", "exe"))
		if o.PPID == 0 {
			o.PPID = nestedNum(f, "parent", "pid")
		}
		o.SHA256 = first(str(f, "sha256"), str(f, "exe_sha256"))
		if u := str(f, "user"); u != "" {
			o.User = NormAccount(u)
		}
	case KindFileChange:
		o.Class = ClassFile
		o.Path = str(f, "path")
		o.Op = str(f, "op")
		o.Sweep = str(f, "source") == "sweep"
		// Linux audit carries the writer as pid/exe, Sysmon as actor_*.
		if _, ok := f["actor_pid"]; ok {
			o.PID, o.Exe = num(f, "actor_pid"), str(f, "actor_exe")
		} else if !o.Sweep {
			o.PID, o.Exe = num(f, "pid"), str(f, "exe")
			o.StartTicks = uint64(num(f, "writer_start_ticks"))
		}
		o.Comm = str(f, "comm")
		o.Cmdline = str(f, "writer_cmdline")
		if u := str(f, "user"); u != "" {
			o.User = NormAccount(u)
		}
	case KindConnOpened, KindConnClosed, KindEgressDenied:
		o.Class = ClassConnOpen
		if ev.Kind == KindConnClosed {
			o.Class = ClassConnClose
		} else if ev.Kind == KindEgressDenied {
			o.Class = ClassEgressDenied
		}
		o.Dir = shortDir(str(f, "dir"))
		o.LAddr, o.LPort = str(f, "laddr"), int(num(f, "lport"))
		o.RAddr, o.RPort = str(f, "raddr"), int(num(f, "rport"))
		if o.Class == ClassEgressDenied {
			o.Dir = "out"
			if o.RAddr == "" {
				o.RAddr, o.RPort = str(f, "dst_ip"), int(num(f, "dst_port"))
				if o.RAddr == "" {
					o.RAddr, o.RPort = splitHostPort(str(f, "dst"))
				}
			}
		}
		o.Proto, o.Service, o.CID = str(f, "proto"), str(f, "service"), str(f, "community_id")
		o.PID, o.StartTicks = num(f, "pid"), uint64(num(f, "pid_start"))
		o.Exe, o.Comm, o.SHA256 = str(f, "exe"), str(f, "comm"), str(f, "exe_sha256")
	case KindNetConnect:
		o.Class = ClassConnOpen
		o.PID = num(f, "pid")
		o.Exe, o.Comm = str(f, "exe"), str(f, "comm")
		if _, ok := f["src_ip"]; ok { // Sysmon 3
			o.Proto = str(f, "proto")
			o.Dir = shortDir(str(f, "dir"))
			sip, dip := str(f, "src_ip"), str(f, "dst_ip")
			sp, dp := int(num(f, "src_port")), int(num(f, "dst_port"))
			if o.Dir == "in" { // Sysmon reports in the direction of the connection
				o.RAddr, o.RPort, o.LAddr, o.LPort = sip, sp, dip, dp
			} else {
				o.LAddr, o.LPort, o.RAddr, o.RPort = sip, sp, dip, dp
			}
			if o.Proto == "tcp" || o.Proto == "udp" {
				o.CID = cidOf(o.Proto, sip, sp, dip, dp)
			}
		} else { // Linux audit connect/accept: only the peer is known
			o.Dir = shortDir(str(f, "direction"))
			o.RAddr, o.RPort = str(f, "addr"), int(num(f, "port"))
		}
	case KindAuthSuccess, KindAuthFail:
		o.Class = ClassAuthOK
		if ev.Kind == KindAuthFail {
			o.Class = ClassAuthFail
		}
		o.Account = NormAccount(first(str(f, "account"), str(f, "user")))
		o.Source = str(f, "source")
		o.SourcePort = int(num(f, "source_port"))
		o.Service, o.Method = str(f, "service"), str(f, "method")
		o.LogonType = int(num(f, "logon_type"))
		o.Exe = str(f, "process")
	case KindSecEvent:
		o.Class = ClassSec
		o.Category = str(f, "category")
		o.Account = NormAccount(first(str(f, "account"), str(f, "subject_account")))
		o.Actor = NormAccount(str(f, "subject_account"))
		o.Source = str(f, "source")
		o.Path = first(str(f, "image_path"), str(f, "path"))
		o.Op = str(f, "op")
		o.PID = num(f, "pid")
		o.Exe = first(str(f, "exe"), str(f, "image_path"))
	}
	return o
}

func cidOf(proto, sip string, sp int, dip string, dp int) string {
	a, err1 := netip.ParseAddr(sip)
	b, err2 := netip.ParseAddr(dip)
	if err1 != nil || err2 != nil {
		return ""
	}
	p := uint8(netmod.ProtoTCP)
	if proto == "udp" {
		p = netmod.ProtoUDP
	}
	return netmod.CommunityID(0, p, netip.AddrPortFrom(a, uint16(sp)), netip.AddrPortFrom(b, uint16(dp)))
}

// Peer returns the remote address an event involves, if any.
func (o Obs) Peer() string {
	switch o.Class {
	case ClassConnOpen, ClassConnClose, ClassEgressDenied:
		return o.RAddr
	case ClassAuthOK, ClassAuthFail, ClassSec:
		return o.Source
	}
	return genericPeer(o.Ev.Fields)
}

// genericPeer finds a peer address in events of kinds this package does not
// model (decoy hits, honeytoken sightings, transaction logs).
func genericPeer(f map[string]any) string {
	for _, k := range []string{"source", "src_ip", "client", "client_ip", "remote_addr", "raddr", "peer", "addr"} {
		if s := str(f, k); s != "" {
			if _, err := netip.ParseAddr(s); err == nil {
				return s
			}
		}
	}
	return ""
}

// NormAccount lower-cases an account and strips a DOMAIN\ or @realm part, so
// "CORP\Svc_Backup", "svc_backup@corp.local" and "svc_backup" compare equal.
func NormAccount(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '\\'); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.IndexByte(s, '@'); i > 0 {
		s = s[:i]
	}
	s = strings.ToLower(s)
	if s == "-" {
		return ""
	}
	return s
}

// IsLoopback reports whether addr is a loopback address.
func IsLoopback(addr string) bool {
	a, err := netip.ParseAddr(addr)
	return err == nil && a.Unmap().IsLoopback()
}

// IsPrivate reports whether addr is a private (RFC 1918, ULA) address.
func IsPrivate(addr string) bool {
	a, err := netip.ParseAddr(addr)
	return err == nil && a.Unmap().IsPrivate()
}

func shortDir(d string) string {
	switch strings.ToLower(d) {
	case "in", "inbound":
		return "in"
	case "out", "outbound":
		return "out"
	}
	return ""
}

func splitHostPort(s string) (string, int) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return "", 0
	}
	return ap.Addr().String(), int(ap.Port())
}

func first(a ...string) string {
	for _, s := range a {
		if s != "" {
			return s
		}
	}
	return ""
}

func str(f map[string]any, k string) string {
	switch v := f[k].(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	}
	return ""
}

func nestedStr(f map[string]any, k1, k2 string) string {
	if m, ok := f[k1].(map[string]any); ok {
		return str(m, k2)
	}
	return ""
}

func nestedNum(f map[string]any, k1, k2 string) int64 {
	if m, ok := f[k1].(map[string]any); ok {
		return num(m, k2)
	}
	return 0
}

func num(f map[string]any, k string) int64 {
	switch v := f[k].(type) {
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return i
		}
		if x, err := v.Float64(); err == nil {
			return int64(x)
		}
	case int:
		return int64(v)
	case int64:
		return v
	case uint64:
		return int64(v)
	case uint32:
		return int64(v)
	case float64:
		return int64(v)
	case string:
		if i, err := strconv.ParseInt(v, 0, 64); err == nil {
			return i
		}
	}
	return 0
}
