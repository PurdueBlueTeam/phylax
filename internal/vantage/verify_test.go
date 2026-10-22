package vantage

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/checks"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/scorer"
	"github.com/PurdueBlueTeam/phylax/internal/vault"
)

// pop3 starts a fake POP3 server that accepts user:pass.
func pop3(t *testing.T, user, pass string) checks.Spec {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				fmt.Fprint(c, "+OK hi\r\n")
				var u string
				for {
					ln, err := r.ReadString('\n')
					if err != nil {
						return
					}
					cmd, arg, _ := strings.Cut(strings.TrimSpace(ln), " ")
					switch cmd {
					case "USER":
						u = arg
						fmt.Fprint(c, "+OK\r\n")
					case "PASS":
						if u == user && arg == pass {
							fmt.Fprint(c, "+OK\r\n")
						} else {
							fmt.Fprint(c, "-ERR no\r\n")
						}
					case "NOOP":
						fmt.Fprint(c, "+OK\r\n")
					case "STAT":
						fmt.Fprint(c, "+OK 0 0\r\n")
					case "QUIT":
						fmt.Fprint(c, "+OK\r\n")
						return
					}
				}
			}()
		}
	}()
	a := l.Addr().(*net.TCPAddr)
	return checks.Spec{ID: fmt.Sprintf("pop3-%d", a.Port), Type: checks.POP3, Host: "127.0.0.1", Port: a.Port}
}

func TestVerifyServiceAndRemoteVerifier(t *testing.T) {
	allow, _ := ParseAllowlist("127.0.0.1")
	okA, okB := pop3(t, "alice", "NewPass-1"), pop3(t, "alice", "NewPass-1")
	bobOK, bobStale := pop3(t, "bob", "NewPass-1"), pop3(t, "bob", "OldPass-0") // a host where the change did not land
	byAcct := map[string][]checks.Spec{"alice": {okA, okB}, "bob": {bobOK, bobStale}, "ghost": nil}
	vs, err := NewVerifyService(VerifyConfig{Allow: allow, Probe: checks.Options{Timeout: 2 * time.Second},
		Targets: func(a string) []checks.Spec { return byAcct[a] }})
	if err != nil {
		t.Fatal(err)
	}
	s := &sink{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go vs.Start(ctx, s.emit)
	eventually(t, time.Second, "module started", func() bool { return vs.emit.Load() != nil })

	var v scorer.Verifier = &RemoteVerifier{T: LocalTransport{vs}}

	if err := v.Login(ctx, "alice", vault.NewSecretString("NewPass-1")); err != nil {
		t.Fatalf("alice: %v", err)
	}
	ev := s.kind(KindPCRVerify)
	if len(ev) != 1 || ev[0].Fields["ok"] != true || ev[0].Priority != event.PriorityNormal {
		t.Fatalf("%+v", ev)
	}

	// wrong password on the public path: V4, critical
	err = v.Login(ctx, "alice", vault.NewSecretString("WrongPass-9"))
	if err == nil || !strings.Contains(err.Error(), "login failed") {
		t.Fatalf("expected a login failure, got %v", err)
	}
	ev = s.kind(KindPCRVerify)
	if len(ev) != 2 || ev[1].Fields["ok"] != false || ev[1].Priority != event.PriorityCritical {
		t.Fatalf("%+v", ev)
	}
	b, _ := json.Marshal(ev)
	if strings.Contains(string(b), "WrongPass-9") || strings.Contains(string(b), "NewPass-1") {
		t.Fatalf("a password leaked into the event: %s", b)
	}

	// success must hold on EVERY public service of the account
	if err := v.Login(ctx, "bob", vault.NewSecretString("NewPass-1")); err == nil {
		t.Fatal("bob's credential is rejected by the stale host; verification must fail")
	}
	res := vs.Handle(ctx, VerifyRequest{Account: "bob", Pass: vault.NewSecretString("NewPass-1")})
	if res.OK || len(res.Services) != 2 || !res.Services[0].OK || res.Services[1].OK {
		t.Fatalf("%+v", res)
	}

	// nothing to verify against is a failure, not a pass
	if err := v.Login(ctx, "ghost", vault.NewSecretString("x")); err == nil || !strings.Contains(err.Error(), ErrNoPublicPath.Error()) {
		t.Fatalf("ghost: %v", err)
	}

	// a non-allowlisted target is never contacted
	byAcct["evil"] = []checks.Spec{{ID: "x", Type: checks.POP3, Host: "198.51.100.9", Port: 110}}
	if res := vs.Handle(ctx, VerifyRequest{Account: "evil", Pass: vault.NewSecretString("x")}); res.OK || res.Services[0].Err != "target is not allowlisted" {
		t.Fatalf("%+v", res)
	}
}

type errTransport struct{}

func (errTransport) Verify(context.Context, VerifyRequest) (VerifyResult, error) {
	return VerifyResult{}, errors.New("kali unreachable")
}

func TestRemoteVerifierTransportError(t *testing.T) {
	rv := &RemoteVerifier{T: errTransport{}}
	if err := rv.Login(context.Background(), "a", vault.NewSecretString("p")); err == nil || !strings.Contains(err.Error(), "kali unreachable") {
		t.Fatalf("%v", err)
	}
}

func TestVerifyServiceValidation(t *testing.T) {
	if _, err := NewVerifyService(VerifyConfig{}); err == nil {
		t.Fatal("empty config accepted")
	}
}
