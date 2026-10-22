package smb2

import (
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/capture/fixture"
	"github.com/PurdueBlueTeam/phylax/internal/parsers/parsertest"
	"github.com/PurdueBlueTeam/phylax/internal/scorer"
)

const sess = 0x1000000000001

// quotientSession is the SMB check quotient.md section 6 describes: negotiate,
// NTLM with flags 0xe2888215 whose domain is the server's name, tree
// \\ip:445\share, create/read/close, logoff.
func quotientSession(domain string) []parsertest.Step {
	t1 := fixture.NTLMNegotiate(0xe2088297)
	t2 := fixture.NTLMChallenge("FILESRV", "FILESRV", "filesrv.team21.local", 0xe2898215)
	t3 := fixture.NTLMAuthenticate(domain, "scoring", "WORKSTATION", 0xe2888215)
	return []parsertest.Step{
		parsertest.C2S(fixture.SMB2NegotiateReq(0x0202, 0x0210, 0x0300, 0x0302, 0x0311)),
		parsertest.S2C(fixture.SMB2NegotiateResp(0x0311)),
		parsertest.C2S(fixture.SMB2SessionSetup(false, 0, 1, 0, fixture.SPNEGOWrap(t1))),
		parsertest.S2C(fixture.SMB2SessionSetup(true, statusMore, 1, sess, fixture.SPNEGOWrap(t2))),
		parsertest.C2S(fixture.SMB2SessionSetup(false, 0, 2, sess, fixture.SPNEGOWrap(t3))),
		parsertest.S2C(fixture.SMB2SessionSetup(true, 0, 2, sess, nil)),
		parsertest.C2S(fixture.SMB2TreeConnect(3, sess, `\\172.20.240.100:445\sop`)),
		parsertest.C2S(fixture.SMB2Create(4, 1, sess, `docs\sop1.txt`)),
		parsertest.S2C(fixture.SMB2ReadResp(5, 1, sess, 9000)),
		parsertest.C2S(fixture.SMB2Logoff(false, 7, sess)),
		parsertest.S2C(fixture.SMB2Logoff(true, 7, sess)),
	}
}

func TestQuotientSMBSession(t *testing.T) {
	for _, n := range []int{1 << 20, 17, 1} {
		out := parsertest.Run(New, parsertest.Resegment(quotientSession("FILESRV"), n)...)
		if len(out) != 1 {
			t.Fatalf("n=%d got %d txns", n, len(out))
		}
		x := out[0]
		if got := x.List["smb.dialects"]; len(got) != 5 || got[0] != "0x0202" || got[4] != "0x0311" || x.Attr["smb.dialect"] != "0x0311" {
			t.Fatalf("dialects %v %v", got, x.Attr["smb.dialect"])
		}
		if x.Attr["smb.ntlm_flags"] != "0xe2888215" || x.Attr["smb.user"] != "scoring" || x.Attr["smb.domain"] != "FILESRV" ||
			x.Attr["smb.workstation"] != "WORKSTATION" || x.Attr["smb.ntlm_version"] != "10.0.19041" {
			t.Fatalf("ntlm %v", x.Attr)
		}
		if x.Attr["smb.domain_is_server"] != "true" || x.Attr["smb.auth_ok"] != "true" || x.Attr["smb.tree"] != `\\172.20.240.100:445\sop` {
			t.Fatalf("attrs %v", x.Attr)
		}
		if len(x.List["smb.files"]) != 1 || x.List["smb.files"][0] != `docs\sop1.txt` || x.Attr["smb.read_bytes"] != "9000" || x.Attr["smb.logoff"] != "true" {
			t.Fatalf("files/reads %v %v", x.List, x.Attr)
		}
		if x.Cred.User != "scoring" || x.Cred.Domain != "FILESRV" || x.Cred.PassHash != "" {
			t.Fatalf("cred %+v", x.Cred)
		}
	}
	cl, _ := scorer.NewClassifier(scorer.DefaultTable())
	r := cl.Classify(parsertest.Run(New, quotientSession("FILESRV")...)[0].Features())
	for _, id := range []string{"smb.ntlm_flags", "smb.tree", "smb.domain_server"} {
		if !r.HasEvidence(id) {
			t.Fatalf("missing %s: %+v", id, r)
		}
	}
	if r.Verdict != scorer.VerdictScorer {
		t.Fatalf("verdict %s %.2f", r.Verdict, r.Score)
	}
}

func TestDomainNotServerAndFailedAuth(t *testing.T) {
	steps := quotientSession("TEAM21")
	steps[5] = parsertest.S2C(fixture.SMB2SessionSetup(true, 0xC000006D, 2, 0, nil))
	x := parsertest.Run(New, steps...)[0]
	if x.Attr["smb.domain_is_server"] != "false" || x.Attr["smb.auth_ok"] != "false" || x.Attr["smb.auth_status"] != "0xc000006d" {
		t.Fatalf("%v", x.Attr)
	}
}

func TestCompoundAndSMB1Negotiate(t *testing.T) {
	a := fixture.SMB2TreeConnect(3, sess, `\\h\a`)[4:]
	b := fixture.SMB2Create(4, 1, sess, "f")[4:]
	// chain: set NextCommand in the first header to the padded length of the first message
	pad := (len(a) + 7) &^ 7
	a = append(append([]byte(nil), a...), make([]byte, pad-len(a))...)
	a[20], a[21] = byte(pad), byte(pad>>8)
	x := parsertest.Run(New, parsertest.C2S(fixture.NB(append(a, b...))))[0]
	if len(x.List["smb.trees"]) != 1 || len(x.List["smb.files"]) != 1 {
		t.Fatalf("compound: %v", x.List)
	}
	smb1 := []byte{0xff, 'S', 'M', 'B', 0x72, 0, 0, 0, 0, 0x18, 0x01, 0x28}
	smb1 = append(smb1, make([]byte, 32-len(smb1))...)
	dl := append([]byte{2}, []byte("NT LM 0.12\x00")...)
	dl = append(dl, append([]byte{2}, []byte("SMB 2.???\x00")...)...)
	smb1 = append(smb1, 0, byte(len(dl)), 0)
	smb1 = append(smb1, dl...)
	y := parsertest.Run(New, parsertest.C2S(fixture.NB(smb1)))
	if len(y) != 1 || y[0].Attr["smb.smb1"] != "true" || len(y[0].List["smb.dialects"]) != 2 || y[0].List["smb.dialects"][1] != "SMB 2.???" {
		t.Fatalf("smb1: %+v", y)
	}
}

func TestEncryptedAndGarbage(t *testing.T) {
	out := parsertest.Run(New, parsertest.C2S(fixture.NB(append([]byte{0xFD, 'S', 'M', 'B'}, make([]byte, 60)...))))
	if len(out) != 0 {
		t.Fatalf("%v", out)
	}
	_ = parsertest.Run(New, parsertest.C2S([]byte{1, 2, 3, 4, 5, 6}))
	_ = parsertest.Run(New, parsertest.C2S([]byte{0, 0xff, 0xff, 0xff, 0xFE, 'S', 'M', 'B'}))
}

func FuzzSMB2(f *testing.F) { parsertest.Fuzz(f, New, quotientSession("FILESRV")) }
