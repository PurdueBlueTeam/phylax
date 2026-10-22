//go:build windows

package actions

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/PurdueBlueTeam/phylax/internal/firewall"
)

// platformWinEnv wires the native Windows backends. Not exercised by the Linux
// unit tests (they use fakes); needs a Windows lab run.
func platformWinEnv(w *WinEnv) {
	w.Reg = NativeRegistry{}
	w.Svc = SCMConfig{}
	w.Audit = ExecAudit{Exec: w.Exec}
	w.Events = WinEventLog{}
	w.Defender = ExecDefender{Reg: w.Reg, Exec: w.Exec}
	w.Firewall = firewall.NewComBackend
	w.AD = &ADSI{}
}

// ---- registry ----

// NativeRegistry reads and writes HKLM (64-bit view) with the registry API.
type NativeRegistry struct{}

func openHKLM(key string, access uint32) (registry.Key, error) {
	k, err := normRegKey(key)
	if err != nil {
		return 0, err
	}
	sub := strings.TrimPrefix(k, `HKLM\`)
	return registry.OpenKey(registry.LOCAL_MACHINE, sub, access|registry.WOW64_64KEY)
}

func (NativeRegistry) Get(_ context.Context, key, name string) (RegValue, bool, error) {
	k, err := openHKLM(key, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return RegValue{}, false, nil
	}
	if err != nil {
		return RegValue{}, false, err
	}
	defer k.Close()
	_, typ, err := k.GetValue(name, nil)
	if errors.Is(err, registry.ErrNotExist) {
		return RegValue{}, false, nil
	}
	if err != nil && !errors.Is(err, windows.ERROR_MORE_DATA) {
		return RegValue{}, false, err
	}
	switch typ {
	case registry.DWORD, registry.QWORD:
		n, _, err := k.GetIntegerValue(name)
		t := "dword"
		if typ == registry.QWORD {
			t = "qword"
		}
		return RegValue{Type: t, Num: n}, err == nil, err
	case registry.SZ, registry.EXPAND_SZ:
		s, _, err := k.GetStringValue(name)
		t := "sz"
		if typ == registry.EXPAND_SZ {
			t = "expand_sz"
		}
		return RegValue{Type: t, Str: s}, err == nil, err
	case registry.MULTI_SZ:
		m, _, err := k.GetStringsValue(name)
		return RegValue{Type: "multi_sz", Multi: m}, err == nil, err
	default:
		b, _, err := k.GetBinaryValue(name)
		return RegValue{Type: "binary", Bin: b}, err == nil, err
	}
}

func (NativeRegistry) Set(_ context.Context, key, name string, v RegValue) error {
	k, err := normRegKey(key)
	if err != nil {
		return err
	}
	h, _, err := registry.CreateKey(registry.LOCAL_MACHINE, strings.TrimPrefix(k, `HKLM\`), registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return err
	}
	defer h.Close()
	switch v.Type {
	case "dword":
		return h.SetDWordValue(name, uint32(v.Num))
	case "qword":
		return h.SetQWordValue(name, v.Num)
	case "sz":
		return h.SetStringValue(name, v.Str)
	case "expand_sz":
		return h.SetExpandStringValue(name, v.Str)
	case "multi_sz":
		return h.SetStringsValue(name, v.Multi)
	case "binary":
		return h.SetBinaryValue(name, v.Bin)
	}
	return fmt.Errorf("unknown registry type %q", v.Type)
}

func (NativeRegistry) Delete(_ context.Context, key, name string) error {
	k, err := openHKLM(key, registry.SET_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.DeleteValue(name); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	return nil
}

func (NativeRegistry) ValueNames(_ context.Context, key string) ([]string, error) {
	k, err := openHKLM(key, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer k.Close()
	return k.ReadValueNames(-1)
}

// ---- service configuration ----

// SCMConfig implements ServiceConfigurer with the service control manager.
type SCMConfig struct{}

func (SCMConfig) open(unit string, access uint32) (*mgr.Mgr, *mgr.Service, error) {
	h, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return nil, nil, err
	}
	m := &mgr.Mgr{Handle: h}
	sh, err := windows.OpenService(h, windows.StringToUTF16Ptr(unit), access)
	if err != nil {
		m.Disconnect()
		return nil, nil, err
	}
	return m, &mgr.Service{Name: unit, Handle: sh}, nil
}

func (c SCMConfig) Config(_ context.Context, unit string) (SvcConfig, error) {
	m, s, err := c.open(unit, windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return SvcConfig{}, nil
	}
	if err != nil {
		return SvcConfig{}, err
	}
	defer m.Disconnect()
	defer s.Close()
	cfg, err := s.Config()
	if err != nil {
		return SvcConfig{}, err
	}
	q, err := s.Query()
	if err != nil {
		return SvcConfig{}, err
	}
	out := SvcConfig{Exists: true, Binary: cfg.BinaryPathName, Account: cfg.ServiceStartName,
		Running: q.State == svc.Running || q.State == svc.StartPending}
	switch cfg.StartType {
	case mgr.StartAutomatic:
		out.Start = "auto"
		if cfg.DelayedAutoStart {
			out.Start = "auto_delayed"
		}
	case mgr.StartDisabled:
		out.Start = "disabled"
	default:
		out.Start = "manual"
	}
	return out, nil
}

func (c SCMConfig) SetStart(_ context.Context, unit, start string) error {
	m, s, err := c.open(unit, windows.SERVICE_QUERY_CONFIG|windows.SERVICE_CHANGE_CONFIG)
	if err != nil {
		return err
	}
	defer m.Disconnect()
	defer s.Close()
	cfg, err := s.Config()
	if err != nil {
		return err
	}
	cfg.DelayedAutoStart = false
	switch start {
	case "auto":
		cfg.StartType = mgr.StartAutomatic
	case "auto_delayed":
		cfg.StartType, cfg.DelayedAutoStart = mgr.StartAutomatic, true
	case "manual":
		cfg.StartType = mgr.StartManual
	case "disabled":
		cfg.StartType = mgr.StartDisabled
	default:
		return fmt.Errorf("unknown start type %q", start)
	}
	return s.UpdateConfig(cfg)
}

// ---- event log ----

// WinEventLog counts events with wevtapi (EvtQuery).
type WinEventLog struct{}

var (
	modWevtapi   = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtQuery = modWevtapi.NewProc("EvtQuery")
	procEvtNext  = modWevtapi.NewProc("EvtNext")
	procEvtClose = modWevtapi.NewProc("EvtClose")
)

const (
	evtQueryChannelPath      = 0x1
	evtQueryReverseDirection = 0x200
)

func (WinEventLog) Count(ctx context.Context, channel string, ids []int, since time.Time) (EventCount, error) {
	var conds []string
	for _, id := range ids {
		conds = append(conds, fmt.Sprintf("EventID=%d", id))
	}
	q := fmt.Sprintf("*[System[(%s) and TimeCreated[@SystemTime>='%s']]]", strings.Join(conds, " or "), since.UTC().Format("2006-01-02T15:04:05.000Z"))
	cp, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		return EventCount{}, err
	}
	qp, err := windows.UTF16PtrFromString(q)
	if err != nil {
		return EventCount{}, err
	}
	h, _, e := procEvtQuery.Call(0, uintptr(unsafe.Pointer(cp)), uintptr(unsafe.Pointer(qp)), evtQueryChannelPath|evtQueryReverseDirection)
	if h == 0 {
		if errors.Is(e, windows.Errno(15007)) { // channel not found
			return EventCount{}, nil
		}
		return EventCount{}, e
	}
	defer procEvtClose.Call(h)
	var c EventCount
	buf := make([]uintptr, 64)
	for {
		if err := ctx.Err(); err != nil {
			return c, err
		}
		var n uint32
		r, _, e := procEvtNext.Call(h, uintptr(len(buf)), uintptr(unsafe.Pointer(&buf[0])), 1000, 0, uintptr(unsafe.Pointer(&n)))
		if r == 0 {
			if errors.Is(e, windows.ERROR_NO_MORE_ITEMS) || errors.Is(e, windows.Errno(258)) { // no more / timeout
				return c, nil
			}
			return c, e
		}
		for i := uint32(0); i < n; i++ {
			procEvtClose.Call(buf[i])
		}
		c.N += int(n)
		if c.N > 100000 {
			return c, nil
		}
	}
}
