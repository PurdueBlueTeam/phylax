package probe

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func reader(c net.Conn) *bufio.Reader { return bufio.NewReader(c) }

func line(r *bufio.Reader) string {
	l, _ := r.ReadString('\n')
	return strings.TrimRight(l, "\r\n")
}

// ---- FTP ----

func startFTP(t *testing.T, rec *recorder, files map[string]string, user, pass string) (string, int) {
	return listen(t, func(c net.Conn) {
		r := reader(c)
		fmt.Fprintf(c, "220 fake ftp\r\n")
		var dl net.Listener
		var authed bool
		var gotUser string
		for {
			l := line(r)
			if l == "" {
				return
			}
			rec.add(l)
			cmd, arg, _ := strings.Cut(l, " ")
			switch strings.ToUpper(cmd) {
			case "USER":
				gotUser = arg
				fmt.Fprintf(c, "331 password please\r\n")
			case "PASS":
				if gotUser == user && arg == pass {
					authed = true
					fmt.Fprintf(c, "230 ok\r\n")
				} else {
					fmt.Fprintf(c, "530 login incorrect\r\n")
				}
			case "FEAT":
				fmt.Fprintf(c, "211-Features:\r\n EPSV\r\n UTF8\r\n211 End\r\n")
			case "TYPE", "OPTS":
				fmt.Fprintf(c, "200 ok\r\n")
			case "EPSV":
				dl, _ = net.Listen("tcp", "127.0.0.1:0")
				fmt.Fprintf(c, "229 Entering Extended Passive Mode (|||%d|)\r\n", dl.Addr().(*net.TCPAddr).Port)
			case "RETR":
				content, ok := files[arg]
				if !authed || !ok || dl == nil {
					fmt.Fprintf(c, "550 no such file\r\n")
					continue
				}
				fmt.Fprintf(c, "150 opening\r\n")
				dc, _ := dl.Accept()
				dc.Write([]byte(content))
				dc.Close()
				dl.Close()
				fmt.Fprintf(c, "226 done\r\n")
			case "QUIT":
				fmt.Fprintf(c, "221 bye\r\n")
				return
			default:
				fmt.Fprintf(c, "502 no\r\n")
			}
		}
	})
}

func TestFTP(t *testing.T) {
	rec := &recorder{}
	sum := sha256.Sum256([]byte("secret file contents"))
	h, p := startFTP(t, rec, map[string]string{"a.txt": "secret file contents"}, "bob", "pw")
	spec := Spec{Type: FTP, Host: h, Port: p}
	good := cred("bob", "pw")
	it := Item{File: "a.txt", SHA256: strings.ToUpper(hex.EncodeToString(sum[:]))}
	r := runOne(spec, &it, &good, Options{})
	if !r.OK {
		t.Fatalf("%+v", r)
	}
	got := strings.Join(rec.all(), "|")
	want := "USER bob|PASS pw|FEAT|TYPE I|OPTS UTF8 ON|EPSV|RETR a.txt|QUIT"
	if got != want {
		t.Errorf("wire sequence\n got %s\nwant %s", got, want)
	}
	if r = runOne(spec, &Item{File: "a.txt", Regex: "contents$"}, &good, Options{}); !r.OK {
		t.Fatalf("%+v", r)
	}
	if r = runOne(spec, &Item{File: "a.txt", SHA256: strings.Repeat("a", 64)}, &good, Options{}); r.OK || r.Err != "file hash did not match" {
		t.Fatalf("%+v", r)
	}
	if r = runOne(spec, &Item{File: "missing"}, &good, Options{}); r.OK {
		t.Fatalf("%+v", r)
	}
	// Quotient: regex wins when both set (hash not consulted); strict requires both
	both := Item{File: "a.txt", Regex: "secret", SHA256: strings.Repeat("a", 64)}
	if r = runOne(spec, &both, &good, Options{}); !r.OK {
		t.Fatalf("scorer takes regex xor hash: %+v", r)
	}
	if r = runOne(spec, &both, &good, Options{Strict: true}); r.OK || !r.ScorerOK {
		t.Fatalf("strict wants both: %+v", r)
	}
	bad := cred("bob", "nope")
	if r = runOne(spec, nil, &bad, Options{}); r.OK || r.Class != ClassAuth {
		t.Fatalf("%+v", r)
	}
	// no credlist: anonymous/anonymous
	rec2 := &recorder{}
	h2, p2 := startFTP(t, rec2, nil, "anonymous", "anonymous")
	if r = runOne(Spec{Type: FTP, Host: h2, Port: p2}, nil, nil, Options{}); !r.OK {
		t.Fatalf("%+v", r)
	}
}

// ---- SMTP ----

func startSMTP(t *testing.T, rec *recorder, advertiseAuth bool, user, pass string, tlsCfg *tls.Config) (string, int) {
	return listen(t, func(c net.Conn) {
		if tlsCfg != nil {
			c = tls.Server(c, tlsCfg)
		}
		r := reader(c)
		fmt.Fprintf(c, "220 fake ESMTP\r\n")
		authed := false
		for {
			l := line(r)
			if l == "" {
				return
			}
			rec.add(l)
			u := strings.ToUpper(l)
			switch {
			case strings.HasPrefix(u, "EHLO"):
				if advertiseAuth {
					fmt.Fprintf(c, "250-fake\r\n250-8BITMIME\r\n250-STARTTLS\r\n250 AUTH PLAIN LOGIN\r\n")
				} else {
					fmt.Fprintf(c, "250 fake\r\n")
				}
			case strings.HasPrefix(u, "AUTH PLAIN "):
				b, _ := base64.StdEncoding.DecodeString(l[11:])
				if string(b) == "\x00"+user+"\x00"+pass {
					authed = true
					fmt.Fprintf(c, "235 ok\r\n")
				} else {
					fmt.Fprintf(c, "535 bad\r\n")
				}
			case strings.HasPrefix(u, "MAIL FROM:"):
				if !authed {
					fmt.Fprintf(c, "530 auth first\r\n")
				} else {
					fmt.Fprintf(c, "250 ok\r\n")
				}
			case strings.HasPrefix(u, "RCPT TO:"):
				fmt.Fprintf(c, "250 ok\r\n")
			case u == "DATA":
				fmt.Fprintf(c, "354 go\r\n")
				var body []string
				for {
					d := line(r)
					if d == "." {
						break
					}
					body = append(body, d)
				}
				rec.add("BODY:" + strings.Join(body, "/"))
				fmt.Fprintf(c, "250 queued\r\n")
			case u == "QUIT":
				fmt.Fprintf(c, "221 bye\r\n")
				return
			default:
				fmt.Fprintf(c, "500 what\r\n")
			}
		}
	})
}

func TestSMTP(t *testing.T) {
	rec := &recorder{}
	h, p := startSMTP(t, rec, true, "alice@team1.local", "pw", nil)
	spec := Spec{Type: SMTP, Host: h, Port: p, Domain: "team1.local", Creds: []Cred{cred("alice", "pw"), cred("bob", "x")}}
	alice := spec.Creds[0]
	r := runOne(spec, nil, &alice, Options{})
	if !r.OK {
		t.Fatalf("%+v", r)
	}
	time.Sleep(100 * time.Millisecond)
	l := rec.all()
	if l[0] != "EHLO localhost" || !strings.HasPrefix(l[1], "AUTH PLAIN ") ||
		l[2] != "MAIL FROM:<alice@team1.local> BODY=8BITMIME" || l[3] != "RCPT TO:<bob@team1.local>" || l[4] != "DATA" {
		t.Errorf("sequence %q", l)
	}
	for _, c := range l {
		if strings.Contains(strings.ToUpper(c), "STARTTLS") {
			t.Error("must never issue STARTTLS")
		}
	}
	body := l[5]
	parts := strings.Split(strings.TrimPrefix(body, "BODY:"), "/")
	if len(parts) != 3 || !strings.HasPrefix(parts[0], "Subject: ") || len(parts[0]) != 9+16 || len(parts[2]) != 64 {
		t.Errorf("body shape %q", body)
	}
	bad := cred("alice", "wrong")
	if r = runOne(spec, nil, &bad, Options{}); r.OK || r.Class != ClassAuth {
		t.Fatalf("%+v", r)
	}
	// server without AUTH and RequireAuth=false: connect+EHLO only
	rec2 := &recorder{}
	h2, p2 := startSMTP(t, rec2, false, "x", "y", nil)
	if r = runOne(Spec{Type: SMTP, Host: h2, Port: p2, Creds: []Cred{alice}}, nil, &alice, Options{}); !r.OK {
		t.Fatalf("%+v", r)
	}
	// RequireAuth forces AUTH even when not advertised
	if r = runOne(Spec{Type: SMTP, Host: h2, Port: p2, RequireAuth: true, Creds: []Cred{alice}}, nil, &alice, Options{}); r.OK {
		t.Fatalf("RequireAuth should attempt AUTH and fail here: %+v", r)
	}
}

func TestSMTPImplicitTLS(t *testing.T) {
	rec := &recorder{}
	h, p := startSMTP(t, rec, true, "alice", "pw", &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}})
	alice := cred("alice", "pw")
	if r := runOne(Spec{Type: SMTP, Host: h, Port: p, Encrypted: true, Creds: []Cred{alice}}, nil, &alice, Options{Strict: true}); !r.OK {
		t.Fatalf("%+v", r)
	}
}

// ---- IMAP / POP3 ----

func startIMAP(t *testing.T, rec *recorder, wantLogin string, tlsCfg *tls.Config) (string, int) {
	return listen(t, func(c net.Conn) {
		if tlsCfg != nil {
			c = tls.Server(c, tlsCfg)
		}
		r := reader(c)
		fmt.Fprintf(c, "* OK IMAP ready\r\n")
		for {
			l := line(r)
			if l == "" {
				return
			}
			tag, rest, _ := strings.Cut(l, " ")
			rec.add(rest)
			switch {
			case strings.HasPrefix(rest, "LOGIN "):
				if rest == wantLogin {
					fmt.Fprintf(c, "%s OK logged in\r\n", tag)
				} else {
					fmt.Fprintf(c, "%s NO bad creds\r\n", tag)
				}
			case strings.HasPrefix(rest, "LIST"):
				fmt.Fprintf(c, "* LIST () \"/\" INBOX\r\n%s OK done\r\n", tag)
			case strings.HasPrefix(rest, "SELECT"):
				fmt.Fprintf(c, "* 3 EXISTS\r\n%s OK [READ-WRITE] selected\r\n", tag)
			case rest == "LOGOUT":
				fmt.Fprintf(c, "* BYE\r\n%s OK bye\r\n", tag)
				return
			default:
				fmt.Fprintf(c, "%s BAD\r\n", tag)
			}
		}
	})
}

func TestIMAP(t *testing.T) {
	rec := &recorder{}
	h, p := startIMAP(t, rec, `LOGIN "carol" "p\"w"`, nil)
	spec := Spec{Type: IMAP, Host: h, Port: p}
	good := cred("carol", `p"w`)
	if r := runOne(spec, nil, &good, Options{}); !r.OK {
		t.Fatalf("%+v", r)
	}
	if got := strings.Join(rec.all(), "|"); got != `LOGIN "carol" "p\"w"|LIST "" "*"|LOGOUT` {
		t.Errorf("sequence %s", got)
	}
	bad := cred("carol", "no")
	if r := runOne(spec, nil, &bad, Options{}); r.OK || r.Class != ClassAuth {
		t.Fatalf("%+v", r)
	}
	if r := runOne(spec, nil, nil, Options{}); !r.OK { // no credlist: passes on connect
		t.Fatalf("%+v", r)
	}
	rec.mu.Lock()
	rec.l = nil
	rec.mu.Unlock()
	if r := runOne(spec, nil, &good, Options{Strict: true}); !r.OK {
		t.Fatalf("%+v", r)
	}
	if got := strings.Join(rec.all(), "|"); !strings.Contains(got, "SELECT INBOX") {
		t.Errorf("strict should SELECT: %s", got)
	}
	// Encrypted: certificate verification is ON, so a self-signed cert fails like the scorer
	h2, p2 := startIMAP(t, &recorder{}, `LOGIN "carol" "pw"`, &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}})
	g2 := cred("carol", "pw")
	if r := runOne(Spec{Type: IMAP, Host: h2, Port: p2, Encrypted: true}, nil, &g2, Options{}); r.OK {
		t.Fatalf("self-signed cert must fail IMAPS: %+v", r)
	}
}

func startPOP3(t *testing.T, rec *recorder, user, pass string) (string, int) {
	return listen(t, func(c net.Conn) {
		r := reader(c)
		fmt.Fprintf(c, "+OK POP3 ready\r\n")
		var u string
		for {
			l := line(r)
			if l == "" {
				return
			}
			rec.add(l)
			cmd, arg, _ := strings.Cut(l, " ")
			switch strings.ToUpper(cmd) {
			case "USER":
				u = arg
				fmt.Fprintf(c, "+OK\r\n")
			case "PASS":
				if u == user && arg == pass {
					fmt.Fprintf(c, "+OK welcome\r\n")
				} else {
					fmt.Fprintf(c, "-ERR bad\r\n")
				}
			case "NOOP":
				fmt.Fprintf(c, "+OK\r\n")
			case "STAT":
				fmt.Fprintf(c, "+OK 2 1234\r\n")
			case "QUIT":
				fmt.Fprintf(c, "+OK bye\r\n")
				return
			}
		}
	})
}

func TestPOP3(t *testing.T) {
	rec := &recorder{}
	h, p := startPOP3(t, rec, "dave", "pw")
	spec := Spec{Type: POP3, Host: h, Port: p}
	good := cred("dave", "pw")
	if r := runOne(spec, nil, &good, Options{Strict: true}); !r.OK {
		t.Fatalf("%+v", r)
	}
	if got := strings.Join(rec.all(), "|"); got != "USER dave|PASS pw|NOOP|STAT|QUIT" {
		t.Errorf("sequence %s", got)
	}
	bad := cred("dave", "x")
	if r := runOne(spec, nil, &bad, Options{}); r.OK || r.Class != ClassAuth {
		t.Fatalf("%+v", r)
	}
}
