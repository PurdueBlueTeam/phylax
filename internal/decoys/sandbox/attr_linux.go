package sandbox

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// sysProcAttr returns the credential drop for the child. Dropping needs root;
// a non-root agent (a lab run, tests) cannot change identity, so the child runs
// as the agent's own user and only no_new_privs applies (dropped=false).
func sysProcAttr(userName string) (attr *syscall.SysProcAttr, dropped bool, err error) {
	if userName == "-" || os.Geteuid() != 0 {
		return &syscall.SysProcAttr{}, false, nil
	}
	if userName == "" {
		userName = "nobody"
	}
	uid, gid := uint32(65534), uint32(65534)
	if u, err := user.Lookup(userName); err == nil {
		a, e1 := strconv.ParseUint(u.Uid, 10, 32)
		b, e2 := strconv.ParseUint(u.Gid, 10, 32)
		if e1 == nil && e2 == nil {
			uid, gid = uint32(a), uint32(b)
		}
	} else if userName != "nobody" {
		return nil, false, fmt.Errorf("sandbox user %q: %w", userName, err)
	}
	if uid == 0 {
		return nil, false, fmt.Errorf("sandbox user %q is root", userName)
	}
	return &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}}}, true, nil
}

// noNewPrivs makes the process (and its descendants) unable to gain privilege
// through setuid binaries or file capabilities.
const noNewPrivsSupported = true

func noNewPrivs() error { return unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) }
