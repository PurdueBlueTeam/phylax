package netmod

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/event"
)

type collector struct {
	mu  sync.Mutex
	evs []event.Event
}

func (c *collector) emit(e event.Event) error {
	c.mu.Lock()
	c.evs = append(c.evs, e)
	c.mu.Unlock()
	return nil
}
func (c *collector) wait(t *testing.T, kind string) event.Event {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		for _, e := range c.evs {
			if e.Kind == kind {
				c.mu.Unlock()
				return e
			}
		}
		c.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no %s event", kind)
	return event.Event{}
}

func TestModuleRunsUnderSupervisor(t *testing.T) {
	src := &fakeSocks{s: []Sock{lsn("tcp", "0.0.0.0:22", 1)}}
	feed := make(chan NFLogPacket, 4)
	m := New(Config{Interval: 20 * time.Millisecond, Source: src, Procs: fakeProcs{1: {PID: 3, Comm: "sshd"}}, Feed: feed,
		Services: map[string]string{"22": "ssh"}})
	var c collector
	sup := agent.NewSupervisor(agent.SupervisorOptions{Emit: c.emit})
	if err := sup.Add(agent.ModuleSpec{Module: m}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { sup.Run(ctx); close(done) }()

	if e := c.wait(t, KindListenerAdded); e.Fields["service"] != "ssh" {
		t.Errorf("%v", e.Fields)
	}
	src.add(est("tcp", "10.0.0.5:22", "10.0.0.9:555", 2))
	if e := c.wait(t, KindConnectionOpened); e.Fields["dir"] != "inbound" {
		t.Errorf("%v", e.Fields)
	}
	cancel()
	<-done
	if sup.Snapshot()["net"].Emitted < 2 {
		t.Errorf("supervisor saw %+v", sup.Snapshot()["net"])
	}
}

func TestModuleEgressViaFeed(t *testing.T) {
	src := &fakeSocks{s: []Sock{{Proto: "tcp", Local: mustAP("10.0.0.5:40000"), Remote: mustAP("198.51.100.7:4444"), State: StateSynSent, Inode: 9}}}
	feed := make(chan NFLogPacket, 4)
	m := New(Config{Interval: time.Hour, Source: src, Procs: fakeProcs{9: {PID: 8, Comm: "bash", ExeSHA256: "ff"}}, Feed: feed})
	var c collector
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Start(ctx, c.emit)
	feed <- syn("10.0.0.5", "198.51.100.7", 40000, 4444)
	e := c.wait(t, KindEgressDenied)
	if e.Fields["pid"] != 8 || e.Fields["exe_sha256"] != "ff" || e.Priority != event.PriorityHigh {
		t.Errorf("%v", e)
	}
}

func TestCanaryProbe(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tg := CanaryTarget{Addr: mustAddr("127.0.0.1"), Port: uint16(ln.Addr().(*net.TCPAddr).Port), Tag: "kali"}
	e := ProbeCanary(context.Background(), tg, time.Second)
	if e.Fields["result"] != "leak" || e.Fields["expected"] != false || e.Priority != event.PriorityCritical {
		t.Errorf("open port should leak: %v", e.Fields)
	}
	ln.Close()
	e = ProbeCanary(context.Background(), tg, time.Second)
	if e.Fields["result"] != "blocked" || e.Fields["detail"] != "refused" || e.Fields["expected"] != true || e.Fields["canary_tag"] != "kali" {
		t.Errorf("closed port should be blocked: %v", e.Fields)
	}
}
