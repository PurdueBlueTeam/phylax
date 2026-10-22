//go:build linux

package audit

import (
	"errors"
	"testing"
	"time"
)

// Opens a real NETLINK_AUDIT socket (no group, no privileges needed: it only
// listens and never configures anything) and checks that a blocked reader can
// be stopped, which go-libaudit's own client cannot do.
func TestRawNetlinkInterruptAndClose(t *testing.T) {
	nl, err := newRawNetlink(0, 1<<20)
	if err != nil {
		t.Skipf("cannot open a NETLINK_AUDIT socket here: %v", err)
	}
	if nl.rcvbuf <= 0 {
		t.Fatalf("rcvbuf %d", nl.rcvbuf)
	}
	res := make(chan error, 1)
	go func() {
		_, err := nl.Receive(false, nil)
		res <- err
	}()
	time.Sleep(100 * time.Millisecond)
	nl.Interrupt()
	select {
	case err := <-res:
		if !errors.Is(err, errInterrupted) {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("blocked Receive was not interrupted")
	}
	// Non-blocking receive on an idle socket returns EAGAIN, not a hang.
	nl.Resume()
	if _, err := nl.Receive(true, nil); err == nil {
		t.Fatal("expected EAGAIN")
	}
	if err := nl.Close(); err != nil {
		t.Fatal(err)
	}
	if err := nl.Close(); err != nil { // idempotent
		t.Fatal(err)
	}
}
