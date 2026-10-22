package scorer

import (
	"strings"
	"testing"
)

func mustClassifier(t *testing.T) *Classifier {
	t.Helper()
	c, err := NewClassifier(DefaultTable())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestFingerprints(t *testing.T) {
	c := mustClassifier(t)
	cases := []struct {
		name    string
		f       Features
		verdict string
		min     float64
		max     float64
	}{
		{"ssh scorer real login", Features{Proto: "ssh", InBurst: true, OneShot: true, LearnedCred: true,
			Attr: map[string]string{"ssh.hassh": "a7230c16ea72e6ff36f15892c8d4d569", "ssh.pty": "xterm 40x80", "ssh.dwell_ms": "1310"},
			List: map[string][]string{"ssh.auth": {"none", "password"}}}, VerdictScorer, 0.95, 1},
		{"ssh BadAttempts hassh", Features{Proto: "ssh", InBurst: true,
			Attr: map[string]string{"ssh.hassh": "0a07365cc01fa9fc82608ba4019af499", "ssh.fail_then_accept": "true"}}, VerdictScorer, 0.9, 1},
		{"ssh OpenSSH client brute force", Features{Proto: "ssh",
			Attr: map[string]string{"ssh.hassh": "deadbeefdeadbeefdeadbeefdeadbeef", "ssh.dwell_ms": "40"},
			List: map[string][]string{"ssh.auth": {"password"}}}, VerdictUnknown, 0, 0.1},
		{"http scorer", Features{Proto: "http", InBurst: true, OneShot: true,
			Attr: map[string]string{"http.host": "10.0.21.10:80", "http.ua": "Mozilla/4.0 (compatible; MSIE 5.5)"},
			List: map[string][]string{"http.headers": {"Host", "User-Agent", "Accept-Encoding", "Connection"}}}, VerdictScorer, 0.8, 1},
		{"http browser", Features{Proto: "http", InBurst: true,
			Attr: map[string]string{"http.host": "10.0.21.10"},
			List: map[string][]string{"http.headers": {"Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding", "Connection"}}}, VerdictNotScorer, 0, 0.3},
		{"tls go 1.25", Features{Proto: "tls", Attr: map[string]string{"tls.ja4": "t13i131000_f57a46bbacb6_ab7e3b40a677", "tls.sni": "", "tls.hello_len": "1500"},
			List: map[string][]string{"tls.alpn": {}}}, VerdictScorer, 0.9, 1},
		{"smtp scorer", Features{Proto: "smtp", InBurst: true,
			Attr: map[string]string{"smtp.ehlo_arg": "localhost", "smtp.mail_ext": "BODY=8BITMIME", "smtp.subject": "0123456789abcdef", "smtp.body": strings.Repeat("ab", 32)},
			List: map[string][]string{"smtp.cmds": {"EHLO", "AUTH", "MAIL", "RCPT", "DATA", "QUIT"}}}, VerdictScorer, 0.95, 1},
		{"smtp human", Features{Proto: "smtp", Attr: map[string]string{"smtp.ehlo_arg": "mail.example.com", "smtp.subject": "Hello"},
			List: map[string][]string{"smtp.cmds": {"EHLO", "STARTTLS", "EHLO", "MAIL", "RCPT", "DATA", "QUIT"}}}, VerdictUnknown, 0, 0.2},
		{"imap", Features{Proto: "imap", InBurst: true, Attr: map[string]string{"imap.tag": "aB3dE9"},
			List: map[string][]string{"imap.cmds": {"LOGIN", "LIST", "LOGOUT"}}}, VerdictLikelyScorer, 0.5, 0.95},
		{"pop3", Features{Proto: "pop3", InBurst: true, List: map[string][]string{"pop3.cmds": {"USER", "PASS", "NOOP", "STAT"}}}, VerdictLikelyScorer, 0.5, 1},
		{"ftp", Features{Proto: "ftp", InBurst: true, List: map[string][]string{"ftp.cmds": {"USER", "PASS", "FEAT", "TYPE", "OPTS", "EPSV", "RETR", "QUIT"}}}, VerdictLikelyScorer, 0.7, 1},
		{"smb", Features{Proto: "smb", InBurst: true, Attr: map[string]string{"smb.ntlm_flags": "0xe2888215", "smb.tree": `\\10.0.21.100:445\share`, "smb.domain_is_server": "true"}}, VerdictScorer, 0.85, 1},
		{"winrm", Features{Proto: "winrm", InBurst: true, Attr: map[string]string{"winrm.method": "POST", "winrm.path": "/wsman", "winrm.ua": "Go-http-client/1.1", "winrm.first_no_auth": "true"}}, VerdictScorer, 0.8, 1},
		{"icmp go-ping", Features{Proto: "icmp", InBurst: true, Attr: map[string]string{"icmp.payload_len": "24", "icmp.seq": "0"}}, VerdictLikelyScorer, 0.5, 1},
		{"icmp ping -c1", Features{Proto: "icmp", Attr: map[string]string{"icmp.payload_len": "56", "icmp.seq": "1"}}, VerdictUnknown, 0, 0.1},
		{"rdp idle hold", Features{Proto: "rdp", InBurst: true, Attr: map[string]string{"tcp.zero_payload": "true", "tcp.hold_ms": "6"}}, VerdictUnknown, 0.4, 0.7},
	}
	for _, tc := range cases {
		r := c.Classify(tc.f)
		if r.Verdict != tc.verdict || r.Score < tc.min || r.Score > tc.max {
			t.Errorf("%s: verdict %s score %.2f (%v), want %s in [%.2f,%.2f]", tc.name, r.Verdict, r.Score, r.Evidence, tc.verdict, tc.min, tc.max)
		}
		if r.TableVersion != DefaultTableVersion {
			t.Errorf("table version missing")
		}
	}
}

func TestSourceAddressAdvisoryOnly(t *testing.T) {
	c := mustClassifier(t)
	r := c.Classify(Features{Proto: "http", AdvisoryRunner: true})
	if r.Score != 0 || r.Verdict == VerdictScorer {
		t.Fatalf("source address alone labelled traffic: %+v", r)
	}
	a := c.Classify(Features{Proto: "ssh", InBurst: true, AdvisoryRunner: true}).Score
	b := c.Classify(Features{Proto: "ssh", InBurst: true}).Score
	if a-b > 0.05 {
		t.Fatalf("advisory hint too strong: %v vs %v", a, b)
	}
}

func TestCustomProtocolCapped(t *testing.T) {
	c := mustClassifier(t)
	r := c.Classify(Features{Proto: "mssql", InBurst: true, OneShot: true, LearnedCred: true})
	if !r.Custom || r.Score > 0.7 {
		t.Fatalf("custom proto: %+v", r)
	}
}

func TestTableVersioningRoundTrip(t *testing.T) {
	tb := DefaultTable()
	tb.Version = "event-2027-11-07"
	for i := range tb.Rules {
		if tb.Rules[i].ID == "tls.ja4" {
			tb.Rules[i].Values = []string{"t13i130000_newhash_newhash"}
		}
	}
	b, err := tb.JSON()
	if err != nil {
		t.Fatal(err)
	}
	tb2, err := ParseTable(b)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewClassifier(tb2)
	if err != nil {
		t.Fatal(err)
	}
	old := Features{Proto: "tls", Attr: map[string]string{"tls.ja4": "t13i131000_f57a46bbacb6_ab7e3b40a677"}}
	new := Features{Proto: "tls", Attr: map[string]string{"tls.ja4": "t13i130000_newhash_newhash"}}
	if c.Classify(old).HasEvidence("tls.ja4") || !c.Classify(new).HasEvidence("tls.ja4") || c.Classify(new).TableVersion != "event-2027-11-07" {
		t.Fatal("event table override not applied")
	}
	if _, err := ParseTable([]byte(`{"rules":[]}`)); err == nil {
		t.Fatal("table without version accepted")
	}
	bad := DefaultTable()
	bad.Rules = append(bad.Rules, Rule{ID: "x", Proto: "http", Kind: MatchRegex, Key: "k", Pattern: "("})
	if _, err := NewClassifier(bad); err == nil {
		t.Fatal("bad regex accepted")
	}
}
