package enroll

import "fmt"

// Class is a fixed SSH push failure class; each names its next step.
type Class string

const (
	ClassAuth        Class = "auth_refused"
	ClassNoShell     Class = "no_shell"
	ClassNoSpace     Class = "no_space"
	ClassSELinux     Class = "selinux_denial"
	ClassTimeout     Class = "timeout"
	ClassHostname    Class = "hostname_mismatch"
	ClassWindowsSSH  Class = "windows_openssh" // banner says Windows: use the console one-liner or WinRM
	ClassHostKey     Class = "hostkey_changed"
	ClassNoHeartbeat Class = "no_heartbeat" // installed and fresh login worked, the agent never connected
	ClassInstall     Class = "install_failed"
)

// Next is the next step the operator follows for this class (one sentence).
func (c Class) Next() string {
	switch c {
	case ClassAuth:
		return "check the vault's default credentials and the host's SSH password policy, then push again"
	case ClassNoShell:
		return "log in on the console and check the account's shell and the SSH server's shell/permit settings"
	case ClassNoSpace:
		return "free space on the install filesystem or choose another install root, then push again"
	case ClassSELinux:
		return "allow the install path under SELinux (or move the install root to a permitted label), then push again"
	case ClassTimeout:
		return "check the host and the management path, then push again"
	case ClassHostname:
		return "fix the manifest host name or the host's hostname; nothing was uploaded"
	case ClassWindowsSSH:
		return "use the console one-liner or WinRM for this host"
	case ClassHostKey:
		return "confirm the host was rebuilt; remove its known_hosts.json line only after that"
	case ClassNoHeartbeat:
		return "check the agent service on the console; it installed but never connected"
	case ClassInstall:
		return "read the install output on the console and fix the service manager or the binary copy"
	}
	return "check the host on the console"
}

// PushError is one host's failure with its class and the detail for the UI.
type PushError struct {
	Host   string
	Class  Class
	Detail string
}

func (e *PushError) Error() string {
	return fmt.Sprintf("enroll: push %s: %s: %s", e.Host, e.Class, e.Detail)
}

// Next is the next step for this failure.
func (e *PushError) Next() string { return e.Class.Next() }
