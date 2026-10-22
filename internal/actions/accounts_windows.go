//go:build windows

package actions

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// NetAccounts implements AccountBackend with the NetUser* / NetLocalGroup*
// APIs on the local machine. Password changes cannot be rolled back (the old
// password is unknowable), so Snapshot returns a zero Rollback.
type NetAccounts struct{}

var (
	netapi32           = windows.NewLazySystemDLL("netapi32.dll")
	procNetUserSetInfo = netapi32.NewProc("NetUserSetInfo")
	procNetUserAdd     = netapi32.NewProc("NetUserAdd")
	procNetUserDel     = netapi32.NewProc("NetUserDel")
	procGroupAdd       = netapi32.NewProc("NetLocalGroupAddMembers")
	procGroupDel       = netapi32.NewProc("NetLocalGroupDelMembers")
	procGroupGet       = netapi32.NewProc("NetLocalGroupGetMembers")
	advapi32           = windows.NewLazySystemDLL("advapi32.dll")
	procLogonUser      = advapi32.NewProc("LogonUserW")
)

const (
	ufAccountDisable  = 0x2
	ufScript          = 0x1
	ufNormalAccount   = 0x200
	userPrivUser      = 1
	nerrUserNotFound  = 2221
	nerrGroupNotFound = 2220
	errNoSuchUser     = 1317
	maxPreferred      = 0xFFFFFFFF
)

type userInfo1 struct {
	Name        *uint16
	Password    *uint16
	PasswordAge uint32
	Priv        uint32
	HomeDir     *uint16
	Comment     *uint16
	Flags       uint32
	ScriptPath  *uint16
}
type userInfo1003 struct{ Password *uint16 }
type userInfo1008 struct{ Flags uint32 }
type localGroupMembersInfo3 struct{ DomainAndName *uint16 }

func netErr(r uintptr) error {
	if r == 0 {
		return nil
	}
	return syscall.Errno(r)
}

func isNotFound(err error) bool {
	return errors.Is(err, syscall.Errno(nerrUserNotFound)) || errors.Is(err, syscall.Errno(errNoSuchUser))
}

func (NetAccounts) Lookup(_ context.Context, name string) (Account, bool, error) {
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return Account{}, false, err
	}
	var buf *byte
	if err := windows.NetUserGetInfo(nil, n, 1, &buf); err != nil {
		if isNotFound(err) {
			return Account{}, false, nil
		}
		return Account{}, false, err
	}
	defer windows.NetApiBufferFree(buf)
	ui := (*userInfo1)(unsafe.Pointer(buf))
	return Account{Name: name, Home: windows.UTF16PtrToString(ui.HomeDir), Locked: ui.Flags&ufAccountDisable != 0}, true, nil
}

// PasswordIs always reports false: verifying would need a logon attempt, and a
// failed attempt against a wrong guess can count toward lockout. The change is
// idempotent, so the action simply applies. VerifyPassword is used after a
// change, when success is expected.
func (NetAccounts) PasswordIs(context.Context, string, string) (bool, error) { return false, nil }

func (NetAccounts) VerifyPassword(_ context.Context, name, plain string) (bool, error) {
	u, _ := windows.UTF16PtrFromString(name)
	d, _ := windows.UTF16PtrFromString(".")
	p, err := windows.UTF16PtrFromString(plain)
	if err != nil {
		return false, err
	}
	var tok windows.Token
	const logon32Network, providerDefault = 3, 0
	r, _, e := procLogonUser.Call(uintptr(unsafe.Pointer(u)), uintptr(unsafe.Pointer(d)), uintptr(unsafe.Pointer(p)),
		logon32Network, providerDefault, uintptr(unsafe.Pointer(&tok)))
	if r != 0 {
		tok.Close()
		return true, nil
	}
	switch e {
	case syscall.Errno(1327), syscall.Errno(1330), syscall.Errno(1331): // restriction, expired, disabled: password itself was right
		return true, nil
	case syscall.Errno(1326):
		return false, nil
	}
	return false, e
}

func (NetAccounts) SetPassword(_ context.Context, name, plain, _ string, mustChange bool) error {
	if plain == "" {
		return errors.New("windows: a plaintext password is required (hashes are not supported)")
	}
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	pw, err := windows.UTF16PtrFromString(plain)
	if err != nil {
		return err
	}
	info := userInfo1003{Password: pw}
	var parm uint32
	r, _, _ := procNetUserSetInfo.Call(0, uintptr(unsafe.Pointer(n)), 1003, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&parm)))
	if err := netErr(r); err != nil {
		return fmt.Errorf("NetUserSetInfo: %w", err)
	}
	if mustChange {
		return errors.New("windows: must_change is not supported")
	}
	return nil
}

func (NetAccounts) SetLocked(_ context.Context, name string, locked bool) error {
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	var buf *byte
	if err := windows.NetUserGetInfo(nil, n, 1, &buf); err != nil {
		return err
	}
	flags := (*userInfo1)(unsafe.Pointer(buf)).Flags
	windows.NetApiBufferFree(buf)
	if locked {
		flags |= ufAccountDisable
	} else {
		flags &^= ufAccountDisable
	}
	info := userInfo1008{Flags: flags}
	var parm uint32
	r, _, _ := procNetUserSetInfo.Call(0, uintptr(unsafe.Pointer(n)), 1008, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&parm)))
	return netErr(r)
}

func (NetAccounts) Create(_ context.Context, c CreateSpec) error {
	if c.Password == "" {
		return errors.New("windows: user.create needs a password")
	}
	n, err := windows.UTF16PtrFromString(c.Name)
	if err != nil {
		return err
	}
	pw, err := windows.UTF16PtrFromString(c.Password)
	if err != nil {
		return err
	}
	cm, _ := windows.UTF16PtrFromString(c.Comment)
	info := userInfo1{Name: n, Password: pw, Priv: userPrivUser, Comment: cm, Flags: ufScript | ufNormalAccount}
	var parm uint32
	r, _, _ := procNetUserAdd.Call(0, 1, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&parm)))
	return netErr(r)
}

func (NetAccounts) Delete(_ context.Context, name string) error {
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	r, _, _ := procNetUserDel.Call(0, uintptr(unsafe.Pointer(n)))
	if err := netErr(r); err != nil && !isNotFound(err) {
		return err
	}
	return nil
}

func (NetAccounts) Members(_ context.Context, group string) ([]string, bool, error) {
	g, err := windows.UTF16PtrFromString(group)
	if err != nil {
		return nil, false, err
	}
	var buf *byte
	var read, total uint32
	var resume uintptr
	r, _, _ := procGroupGet.Call(0, uintptr(unsafe.Pointer(g)), 3, uintptr(unsafe.Pointer(&buf)), maxPreferred,
		uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&resume)))
	if r == nerrGroupNotFound || r == 1376 {
		return nil, false, nil
	}
	if r != 0 && r != 234 { // 234 = ERROR_MORE_DATA
		return nil, false, netErr(r)
	}
	defer windows.NetApiBufferFree(buf)
	var out []string
	for i := uint32(0); i < read; i++ {
		e := (*localGroupMembersInfo3)(unsafe.Add(unsafe.Pointer(buf), uintptr(i)*unsafe.Sizeof(localGroupMembersInfo3{})))
		full := windows.UTF16PtrToString(e.DomainAndName)
		if i := strings.LastIndexByte(full, '\\'); i >= 0 {
			full = full[i+1:]
		}
		out = append(out, full)
	}
	return out, true, nil
}

func (NetAccounts) SetMembers(_ context.Context, group string, add, remove []string) error {
	g, err := windows.UTF16PtrFromString(group)
	if err != nil {
		return err
	}
	do := func(proc *windows.LazyProc, names []string) error {
		if len(names) == 0 {
			return nil
		}
		infos := make([]localGroupMembersInfo3, len(names))
		for i, n := range names {
			p, err := windows.UTF16PtrFromString(n)
			if err != nil {
				return err
			}
			infos[i].DomainAndName = p
		}
		r, _, _ := proc.Call(0, uintptr(unsafe.Pointer(g)), 3, uintptr(unsafe.Pointer(&infos[0])), uintptr(len(infos)))
		return netErr(r)
	}
	if err := do(procGroupAdd, add); err != nil {
		return fmt.Errorf("NetLocalGroupAddMembers: %w", err)
	}
	if err := do(procGroupDel, remove); err != nil {
		return fmt.Errorf("NetLocalGroupDelMembers: %w", err)
	}
	return nil
}

// Snapshot: Windows account changes are not automatically reversible.
func (NetAccounts) Snapshot(context.Context) (Rollback, error) { return Rollback{}, nil }
