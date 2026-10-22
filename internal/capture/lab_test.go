package capture

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/parsers/txn"
	"github.com/PurdueBlueTeam/phylax/internal/scorer"
)

// The lab Quotient capture (a two-team lab run of the real scorer, 84 rounds):
// every parser's features against what the scorer's checks actually send. The
// pcaps are not in the repository; the test skips when they are absent
// (PHYLAX_QLAB overrides /tmp/qlab/final). Results are recorded in
// docs/capture.md.

func labDir(t *testing.T) string {
	t.Helper()
	d := os.Getenv("PHYLAX_QLAB")
	if d == "" {
		d = "/tmp/qlab/final"
	}
	if _, err := os.Stat(filepath.Join(d, "lab_svc1.pcap")); err != nil {
		t.Skipf("lab Quotient pcaps not present in %s (set PHYLAX_QLAB): %v", d, err)
	}
	return d
}

type labRun struct {
	txns  []txn.Txn
	flows []Flow
	scans []Scan
	stats EngineStats
}

func runLab(t *testing.T, name string) labRun {
	t.Helper()
	f, err := os.Open(filepath.Join(labDir(t), name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	src, err := NewPCAPSource(f)
	if err != nil {
		t.Fatal(err)
	}
	var r labRun
	e := NewEngine(Config{
		OnTxn:  func(x txn.Txn) { r.txns = append(r.txns, x) },
		OnFlow: func(x Flow) { r.flows = append(r.flows, x) },
		OnScan: func(x Scan) { r.scans = append(r.scans, x) },
	})
	if err := Run(context.Background(), src, e); err != nil {
		t.Fatal(err)
	}
	r.stats = e.Stats()
	return r
}

func (r labRun) proto(p string) []txn.Txn {
	var out []txn.Txn
	for _, x := range r.txns {
		if x.Proto == p {
			out = append(out, x)
		}
	}
	return out
}

func eq(t *testing.T, what string, x txn.Txn, key, want string) {
	t.Helper()
	if x.Attr[key] != want {
		t.Errorf("%s %s: %s = %q, want %q (%v->%v)", what, x.Time.Format("15:04:05"), key, x.Attr[key], want, x.Client, x.Server)
	}
}

func listEq(t *testing.T, what string, x txn.Txn, key string, want ...string) {
	t.Helper()
	if !slices.Equal(x.List[key], want) {
		t.Errorf("%s %s: %s = %v, want %v", what, x.Time.Format("15:04:05"), key, x.List[key], want)
	}
}

// labPassHashes are the hashes of every credential the lab credlist can hold:
// LabPass-<user>-<n> for the PCR counter n.
func labPassHashes() map[string]string {
	m := map[string]string{}
	for _, u := range []string{"alice", "bob", "carol"} {
		for n := 1; n <= 200; n++ {
			m[txn.HashSecret(fmt.Sprintf("LabPass-%s-%d", u, n))] = u
		}
	}
	return m
}

func TestLabQuotientSvcParsers(t *testing.T) {
	cl, err := scorer.NewClassifier(scorer.DefaultTable())
	if err != nil {
		t.Fatal(err)
	}
	hashes := labPassHashes()
	runners := map[string]bool{}
	for i := 132; i <= 136; i++ {
		runners[fmt.Sprintf("172.28.77.%d", i)] = true
	}
	for _, name := range []string{"lab_svc1.pcap", "lab_svc2.pcap"} {
		t.Run(name, func(t *testing.T) {
			r := runLab(t, name)
			s := r.stats
			if s.DecodeErrors != 0 || s.ParserPanics != 0 || s.ReasmGaps != 0 || s.ReasmCapped != 0 || s.FlowsActive != 0 {
				t.Fatalf("engine stats: %+v", s)
			}
			rounds := len(r.proto("smtp"))
			if rounds < 80 {
				t.Fatalf("only %d smtp sessions", rounds)
			}
			atLeast := func(what string, n int, frac float64) {
				t.Helper()
				if float64(n) < frac*float64(rounds) {
					t.Errorf("%s: %d, want about %d (one or two per round)", what, n, rounds)
				}
			}
			atLeast("ftp", len(r.proto("ftp")), 1)
			atLeast("imap", len(r.proto("imap")), 1)
			atLeast("pop3", len(r.proto("pop3")), 1)
			atLeast("smb", len(r.proto("smb")), 1)
			atLeast("rdp (tcp connect)", len(r.proto("rdp")), 1)
			atLeast("winrm (BadAttempts: two per round)", len(r.proto("winrm")), 1.9)
			atLeast("dns queries", len(r.proto("dns"))/2, 1)

			// Source addresses are the runners', not a firewall: the source
			// address check at drop passes for the lab (no NAT in between).
			for _, x := range r.txns {
				if x.Proto == "smtp" || x.Proto == "ftp" || x.Proto == "smb" || x.Proto == "imap" || x.Proto == "pop3" {
					if !runners[x.Client.Addr().String()] {
						t.Fatalf("%s from %v: not one of the runner addresses", x.Proto, x.Client)
					}
				}
			}

			// A burst can overrun the lab's tcpdump (the client ACKs data that is
			// not in the file), cutting a few in-flight sessions short; the
			// parsers must flush them without error, and they are not held
			// to the full command sequence.
			cut := 0
			full := func(x txn.Txn, key string) bool {
				l := x.List[key]
				if len(l) == 0 || l[len(l)-1] != "QUIT" && l[len(l)-1] != "LOGOUT" && x.Attr["smtp.delivered"] != "1" {
					cut++
					return false
				}
				return true
			}
			defer func() {
				if cut > 6 {
					t.Errorf("%d sessions cut short", cut)
				}
				t.Logf("%d sessions cut short by capture loss in the lab file", cut)
			}()
			hashed, withCred := 0, 0
			for _, x := range r.proto("smtp") {
				if !full(x, "smtp.cmds") {
					continue
				}
				eq(t, "smtp", x, "smtp.ehlo_arg", "localhost")
				eq(t, "smtp", x, "smtp.mail_ext", "BODY=8BITMIME")
				eq(t, "smtp", x, "smtp.auth_mech", "plain")
				eq(t, "smtp", x, "smtp.auth_ok", "true")
				eq(t, "smtp", x, "smtp.body_len", "64")
				eq(t, "smtp", x, "smtp.delivered", "1")
				if len(x.Attr["smtp.subject"]) != 16 {
					t.Errorf("smtp subject %q", x.Attr["smtp.subject"])
				}
				if len(x.Attr["smtp.body"]) != 64 {
					t.Errorf("smtp body %q is not 64 hex digits", x.Attr["smtp.body"])
				}
				listEq(t, "smtp", x, "smtp.cmds", "EHLO", "AUTH", "MAIL", "RCPT", "DATA", "QUIT")
				if len(x.List["smtp.rcpts"]) != 1 || !strings.HasSuffix(x.List["smtp.rcpts"][0], "@lab.test") {
					t.Errorf("smtp rcpts %v", x.List["smtp.rcpts"])
				}
			}
			for _, p := range []string{"smtp", "ftp", "imap", "pop3"} {
				for _, x := range r.proto(p) {
					if x.Cred == nil || x.Cred.PassHash == "" || x.Attr[p+".auth_ok"] != "true" {
						continue // a rotated (PCR) credential is not in the lab list
					}
					withCred++
					u := hashes[x.Cred.PassHash]
					if u != "" && strings.HasPrefix(x.Cred.User, u) {
						hashed++
					} else {
						t.Logf("unrecognised credential: %s %s user=%s hash=%s at %s", p, x.Client, x.Cred.User, x.Cred.PassHash, x.Time.Format("15:04:05"))
					}
					if !slices.Contains(x.Secret, "cred.pass_hash") {
						t.Errorf("%s credential hash is not marked secret", p)
					}
				}
			}
			// The few others are sessions during PCR windows, using the password the
			// scorer was told to change to (one hash shared by all three users).
			if withCred == 0 || hashed < withCred-6 {
				t.Errorf("credential hashes match LabPass-<user>-<n> for %d of %d sessions", hashed, withCred)
			}

			for _, x := range r.proto("ftp") {
				if x.Attr["ftp.auth_ok"] != "true" || !full(x, "ftp.cmds") {
					continue
				}
				listEq(t, "ftp", x, "ftp.cmds", "USER", "PASS", "FEAT", "TYPE", "OPTS", "EPSV", "RETR", "QUIT")
				listEq(t, "ftp", x, "ftp.files", "RETR readme.txt")
				if len(x.List["ftp.data_channels"]) != 1 {
					t.Errorf("ftp data channels %v", x.List["ftp.data_channels"])
				}
				eq(t, "ftp", x, "ftp.transfers_ok", "1")
			}
			for _, x := range r.proto("imap") {
				if x.Attr["imap.auth_ok"] == "true" && full(x, "imap.cmds") {
					listEq(t, "imap", x, "imap.cmds", "LOGIN", "LIST", "LOGOUT")
					eq(t, "imap", x, "imap.auth_mech", "login")
					if len(x.Attr["imap.tag"]) != 6 {
						t.Errorf("imap tag %q", x.Attr["imap.tag"])
					}
				}
			}
			for _, x := range r.proto("pop3") {
				if x.Attr["pop3.auth_ok"] == "true" && full(x, "pop3.cmds") {
					listEq(t, "pop3", x, "pop3.cmds", "USER", "PASS", "NOOP", "STAT", "QUIT")
				}
			}
			smbOK := 0
			for _, x := range r.proto("smb") {
				eq(t, "smb", x, "smb.dialect", "0x0311")
				eq(t, "smb", x, "smb.ntlm_flags", "0xe2888215")
				eq(t, "smb", x, "smb.domain_is_server", "true")
				listEq(t, "smb", x, "smb.dialects", "0x0311", "0x0302", "0x0300", "0x0210", "0x0202")
				if x.Attr["smb.auth_ok"] == "true" {
					smbOK++
					listEq(t, "smb", x, "smb.files", "important.txt")
					if len(x.List["smb.trees"]) != 1 || !strings.HasSuffix(x.List["smb.trees"][0], `\shared`) {
						t.Errorf("smb trees %v", x.List["smb.trees"])
					}
				}
			}
			if smbOK < rounds-8 {
				t.Errorf("%d successful smb sessions of %d rounds", smbOK, rounds)
			}
			noauth, post := 0, 0
			for _, x := range r.proto("winrm") {
				eq(t, "winrm", x, "winrm.method", "POST")
				eq(t, "winrm", x, "winrm.path", "/wsman")
				eq(t, "winrm", x, "winrm.ua", "Go-http-client/1.1")
				post++
				if x.Attr["winrm.first_no_auth"] == "true" {
					noauth++
				}
			}
			if noauth < post/2-4 {
				t.Errorf("winrm first_no_auth %d of %d", noauth, post)
			}
			qtypes := map[string]int{}
			for _, x := range r.proto("dns") {
				if x.Type == "query" {
					qtypes[x.Attr["dns.qtype"]]++
					eq(t, "dns", x, "dns.rd", "true")
					eq(t, "dns", x, "dns.edns", "false")
				}
			}
			if qtypes["A"] < rounds {
				t.Errorf("dns qtypes %v", qtypes)
			}

			echoes, echo24 := 0, 0
			for _, x := range r.proto("icmp") {
				if x.Type != "echo_request" {
					continue
				}
				echoes++
				if x.Attr["icmp.payload_len"] == "24" {
					echo24++
					eq(t, "icmp", x, "icmp.seq", "0")
				}
			}
			if echo24 < rounds {
				t.Errorf("scorer pings (24 byte payload, seq 0): %d of %d echoes, %d rounds", echo24, echoes, rounds)
			}

			hassh := map[string]int{}
			bannerOnly := 0
			for _, x := range r.proto("ssh") {
				if x.Attr["ssh.hassh"] == "" {
					bannerOnly++
					eq(t, "ssh banner-only", x, "ssh.encrypted", "false")
					continue
				}
				eq(t, "ssh", x, "ssh.encrypted", "true")
				hassh[x.Attr["ssh.hassh"]]++
			}
			// BadAttempts is the HASSH without 3des-cbc, the real login the one with it.
			var real string
			for h := range hassh {
				if strings.HasPrefix(h, "a7230c16") {
					real = h
				}
			}
			if hassh["0a07365cc01fa9fc82608ba4019af499"] < rounds-4 || hassh[real] < rounds || len(hassh) != 2 {
				t.Errorf("hassh counts %v", hassh)
			}
			if bannerOnly < rounds {
				t.Errorf("banner-only ssh sessions %d (tcp22 check and pyprobe: two per round)", bannerOnly)
			}

			// The classifier: successful scorer sessions are labelled scorer
			// or likely_scorer; the misses are listed in docs/capture.md.
			verdict := map[string]map[string]int{}
			for _, x := range r.txns {
				if x.OK != nil && !*x.OK {
					continue
				}
				v := cl.Classify(x.Features()).Verdict
				if verdict[x.Proto] == nil {
					verdict[x.Proto] = map[string]int{}
				}
				verdict[x.Proto][v]++
			}
			t.Logf("classifier verdicts: %v", verdict)
			for _, p := range []string{"smtp", "smb", "winrm", "ftp", "imap", "pop3"} {
				v := verdict[p]
				hit := v[scorer.VerdictScorer] + v[scorer.VerdictLikelyScorer]
				tot := 0
				for _, n := range v {
					tot += n
				}
				if float64(hit) < 0.93*float64(tot) {
					t.Errorf("%s: %d of %d labelled scorer: %v", p, hit, tot, v)
				}
			}
		})
	}
}

// web1b: the scorer's HTTP and HTTPS checks and pings against the web box.
func TestLabQuotientWeb(t *testing.T) {
	cl, _ := scorer.NewClassifier(scorer.DefaultTable())
	r := runLab(t, "lab_web1b.pcap")
	if r.stats.DecodeErrors != 0 || r.stats.ParserPanics != 0 {
		t.Fatalf("%+v", r.stats)
	}
	hs := r.proto("http")
	if len(hs) < 50 {
		t.Fatalf("%d http exchanges", len(hs))
	}
	for _, x := range hs {
		eq(t, "http", x, "http.method", "GET")
		eq(t, "http", x, "http.version", "HTTP/1.1")
		listEq(t, "http", x, "http.headers", "Host", "User-Agent", "Accept-Encoding", "Connection")
		if !strings.HasSuffix(x.Attr["http.host"], ":80") {
			t.Errorf("http host %q lacks the scorer's :port", x.Attr["http.host"])
		}
		if res := cl.Classify(x.Features()); !res.HasEvidence("http.header_set") || !res.HasEvidence("http.host_port") {
			t.Errorf("classifier evidence %+v", res.Evidence)
		}
	}
	tl := r.proto("tls")
	scorerHello := 0
	for _, x := range tl {
		// The Go 1.25 client hello recorded in quotient.md section 6.
		if x.Attr["tls.ja4"] == "t13i131000_f57a46bbacb6_ab7e3b40a677" {
			scorerHello++
			eq(t, "tls", x, "tls.ja3", "006598cf32b8feecd39e4337bdba9c44")
			eq(t, "tls", x, "tls.sni", "")
			listEq(t, "tls", x, "tls.alpn")
		}
	}
	if scorerHello < 25 {
		t.Errorf("%d of %d TLS handshakes carry the scorer's JA4", scorerHello, len(tl))
	}
}

// db: a MySQL check no parser covers still produces flows, and the unanswered
// connection attempts to dead ports show up as timed-out flows.
func TestLabQuotientDB(t *testing.T) {
	r := runLab(t, "lab_db.pcap")
	if r.stats.DecodeErrors != 0 || r.stats.ParserPanics != 0 {
		t.Fatalf("%+v", r.stats)
	}
	est, timeout := 0, 0
	for _, f := range r.flows {
		if f.Proto != 6 {
			continue
		}
		switch f.Handshake {
		case "established":
			est++
		case "timeout":
			timeout++
		}
	}
	if est == 0 || timeout == 0 {
		t.Fatalf("established %d, unanswered %d", est, timeout)
	}
	t.Logf("db: %d txns, %d flows (%d established, %d unanswered SYNs)", len(r.txns), len(r.flows), est, timeout)
}
