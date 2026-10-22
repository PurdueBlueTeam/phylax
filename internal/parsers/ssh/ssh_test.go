package ssh

import (
	"strings"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/capture/fixture"
	"github.com/PurdueBlueTeam/phylax/internal/parsers/parsertest"
	"github.com/PurdueBlueTeam/phylax/internal/parsers/txn"
	"github.com/PurdueBlueTeam/phylax/internal/scorer"
	"golang.org/x/crypto/ssh"
)

// The Quotient client KEXINIT (quotient.md section 6) for x/crypto v0.33.0.
const (
	qKex  = "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,ext-info-c,kex-strict-c-v00@openssh.com"
	qEnc  = "aes128-gcm@openssh.com,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr"
	qMac  = "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1,hmac-sha1-96"
	qHost = "rsa-sha2-256,rsa-sha2-512,ssh-rsa,ecdsa-sha2-nistp256,ssh-ed25519"

	hasshReal = "a7230c16ea72e6ff36f15892c8d4d569"
	hasshBad  = "0a07365cc01fa9fc82608ba4019af499"
)

func clientKex(enc string) []byte {
	return fixture.SSHKexInit(1, qKex, qHost, enc, enc, qMac, qMac, "none", "none")
}

func sshSession(enc string) []parsertest.Step {
	return []parsertest.Step{
		parsertest.S2C([]byte("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n")),
		parsertest.C2S([]byte("SSH-2.0-Go\r\n")),
		parsertest.S2C(fixture.SSHKexInit(2, "curve25519-sha256,sntrup761x25519-sha512@openssh.com", "ssh-ed25519", "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com", "umac-128-etm@openssh.com", "umac-128-etm@openssh.com", "none,zlib@openssh.com", "none,zlib@openssh.com")),
		parsertest.C2S(clientKex(enc)),
		parsertest.C2S(fixture.SSHNewKeys()),
		parsertest.S2C(fixture.SSHNewKeys()),
		parsertest.C2S([]byte("\x00\x00\x00\x1c encrypted bytes follow here")),
	}
}

func TestHASSHMatchesQuotientRecordedValues(t *testing.T) {
	// The real login advertises 3des-cbc last in its cipher list; the
	// BadAttempts login does not. Both hashes are quotient.md section 6's.
	for _, c := range []struct {
		name, enc, want string
	}{
		{"real login", qEnc + ",3des-cbc", hasshReal},
		{"BadAttempts", qEnc, hasshBad},
	} {
		out := parsertest.Run(New, sshSession(c.enc)...)
		if len(out) != 1 {
			t.Fatalf("%s: %d txns", c.name, len(out))
		}
		if got := out[0].Attr["ssh.hassh"]; got != c.want {
			t.Fatalf("%s: hassh %s want %s (%s)", c.name, got, c.want, out[0].Attr["ssh.hassh_string"])
		}
	}
}

func TestSessionFeaturesAndClassifier(t *testing.T) {
	steps := sshSession(qEnc + ",3des-cbc")
	out := parsertest.Run(New, steps...)
	x := out[0]
	if x.Attr["ssh.banner"] != "SSH-2.0-Go" || !strings.HasPrefix(x.Attr["ssh.server_banner"], "SSH-2.0-OpenSSH_9.6") {
		t.Fatalf("banners: %v", x.Attr)
	}
	if x.Attr["ssh.hassh_server"] == "" || x.Attr["ssh.encrypted"] != "true" || x.Attr["ssh.kex_seen"] != "true" {
		t.Fatalf("attrs: %v", x.Attr)
	}
	c, _ := scorer.NewClassifier(scorer.DefaultTable())
	if r := c.Classify(x.Features()); !r.HasEvidence("ssh.hassh") || r.Score < 0.85 {
		t.Fatalf("classifier: %+v", r)
	}
	// resegmented one byte at a time gives the same answer
	if o := parsertest.Run(New, parsertest.Resegment(steps, 1)...); len(o) != 1 || o[0].Attr["ssh.hassh"] != hasshReal {
		t.Fatalf("byte-wise: %+v", o)
	}
}

func TestDwellMeasuresConnectionTime(t *testing.T) {
	var out []txn.Txn
	s := New(parsertest.Meta(), func(x txn.Txn) { out = append(out, x) })
	t0 := parsertest.T0
	s.Data(txn.S2C, []byte("SSH-2.0-OpenSSH_9.6\r\n"), t0)
	s.Data(txn.C2S, []byte("SSH-2.0-Go\r\n"), t0.Add(time.Millisecond))
	s.Data(txn.C2S, []byte("late encrypted data"), t0.Add(1300*time.Millisecond))
	s.End(t0.Add(1400 * time.Millisecond))
	if len(out) != 1 || out[0].Attr["ssh.dwell_ms"] != "1300" {
		t.Fatalf("%+v", out)
	}
	c, _ := scorer.NewClassifier(scorer.DefaultTable())
	if !c.Classify(out[0].Features()).HasEvidence("ssh.dwell") {
		t.Fatal("dwell rule did not fire")
	}
}

// TestRealXCryptoClient runs the repository's x/crypto/ssh client against a
// sink. The version in go.mod is newer than Quotient's v0.33.0 and adds a leading
// post-quantum kex, so its HASSH differs from the recorded one; the remaining
// lists are compared to the recorded Quotient lists.
func TestRealXCryptoClient(t *testing.T) {
	c1, c2 := newPipe()
	go func() {
		_, _, _, _ = ssh.NewClientConn(c1, "x:22", &ssh.ClientConfig{User: "u", HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: time.Second})
	}()
	var sent []byte
	buf := make([]byte, 4096)
	defer c1.Close()
	defer c2.Close()
	go func() { _, _ = c2.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n")) }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && len(sent) < 1200 {
		_ = c2.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, err := c2.Read(buf)
		sent = append(sent, buf[:n]...)
		if err != nil && n == 0 && len(sent) > 0 {
			break
		}
		if kexInitSeen(sent) {
			break
		}
	}
	out := parsertest.Run(New, parsertest.S2C([]byte("SSH-2.0-OpenSSH_9.6\r\n")), parsertest.C2S(sent))
	if len(out) != 1 || out[0].Attr["ssh.hassh"] == "" {
		t.Fatalf("no hassh from real client: %+v (%d bytes)", out, len(sent))
	}
	// Quotient's v0.33.0 list plus, in newer x/crypto, a leading mlkem768x25519-sha256:
	// everything else must be exactly what quotient.md section 6 records.
	got := strings.TrimPrefix(out[0].Attr["ssh.hassh_string"], "mlkem768x25519-sha256,")
	if want := qKex + ";" + qEnc + ";" + qMac + ";none"; got != want {
		t.Fatalf("client lists differ from the recorded Quotient lists:\n got %s\nwant %s", got, want)
	}
	t.Logf("x/crypto in go.mod: hassh=%s", out[0].Attr["ssh.hassh"])
}

func kexInitSeen(b []byte) bool {
	i := strings.Index(string(b), "\n")
	if i < 0 || len(b) < i+1+6 {
		return false
	}
	rest := b[i+1:]
	n := int(rest[0])<<24 | int(rest[1])<<16 | int(rest[2])<<8 | int(rest[3])
	return len(rest) >= 4+n
}

func TestMalformedPackets(t *testing.T) {
	for _, in := range [][]byte{
		[]byte("SSH-2.0-x\r\n\xff\xff\xff\xff\x00\x00"),         // absurd length
		[]byte("SSH-2.0-x\r\n\x00\x00\x00\x02\x09\x14"),         // pad >= len
		[]byte("garbage with no banner at all\r\n\x00\x00\x00"), // client must open with a banner
	} {
		_ = parsertest.Run(New, parsertest.C2S(in))
	}
}

func FuzzSSH(f *testing.F) { parsertest.Fuzz(f, New, sshSession(qEnc)) }
