package agent

import (
	"net"
	"os"
)

// sdNotify sends a state string to systemd's notify socket, if any (Type=notify,
// WatchdogSec). It is a no-op outside systemd and on Windows.
func sdNotify(state string) {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return
	}
	if addr[0] == '@' {
		addr = "\x00" + addr[1:]
	}
	c, err := net.Dial("unixgram", addr)
	if err != nil {
		return
	}
	defer c.Close()
	c.Write([]byte(state))
}
