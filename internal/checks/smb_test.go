package checks

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
)

// fakeSMB is a small SMB2 server: negotiate (2.1), NTLM session setup, tree
// connect, create, read, close, tree disconnect, logoff, with optional
// required signing that it enforces on every post-session request.
type fakeSMB struct {
	mu          sync.Mutex
	ntlm        *ntlmServer
	shares      map[string]map[string][]byte
	signing     bool
	treePaths   []string
	cmds        []uint16
	badSig      int
	unsigned    int
	readSizes   []uint32
	dialect     uint16
	reqDialects []uint16
}

func (f *fakeSMB) start(t *testing.T) (string, int) {
	return listen(t, f.serve)
}

func (f *fakeSMB) serve(c net.Conn) {
	var session uint64
	var key []byte
	files := map[uint64]string{}
	var share map[string][]byte
	var authed bool
	for {
		var l [4]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		msg := make([]byte, binary.BigEndian.Uint32(l[:]))
		if _, err := io.ReadFull(c, msg); err != nil {
			return
		}
		cmd := binary.LittleEndian.Uint16(msg[12:])
		flags := binary.LittleEndian.Uint32(msg[16:])
		f.mu.Lock()
		f.cmds = append(f.cmds, cmd)
		f.mu.Unlock()
		body := msg[64:]
		status := uint32(0)
		var rb []byte
		treeID := binary.LittleEndian.Uint32(msg[36:])
		if authed && f.signing {
			f.mu.Lock()
			if flags&smb2FlagSigned == 0 {
				f.unsigned++
			} else {
				cp := append([]byte(nil), msg...)
				copy(cp[48:64], make([]byte, 16))
				m := hmac.New(sha256.New, key)
				m.Write(cp)
				if !hmac.Equal(m.Sum(nil)[:16], msg[48:64]) {
					f.badSig++
				}
			}
			f.mu.Unlock()
		}
		switch cmd {
		case smb2Negotiate:
			n := int(binary.LittleEndian.Uint16(body[2:]))
			var ds []uint16
			for i := range n {
				ds = append(ds, binary.LittleEndian.Uint16(body[36+2*i:]))
			}
			f.mu.Lock()
			f.reqDialects = ds
			f.mu.Unlock()
			rb = make([]byte, 65)
			binary.LittleEndian.PutUint16(rb, 65)
			sm := uint16(1)
			if f.signing {
				sm = 3
			}
			binary.LittleEndian.PutUint16(rb[2:], sm)
			d := f.dialect
			if d == 0 {
				d = 0x0210
			}
			binary.LittleEndian.PutUint16(rb[4:], d)
			binary.LittleEndian.PutUint16(rb[56:], 128)
		case smb2SessionSetup:
			off := int(binary.LittleEndian.Uint16(body[12:])) - 64
			sl := int(binary.LittleEndian.Uint16(body[14:]))
			tok := findNTLM(body[off : off+sl])
			rb = make([]byte, 8)
			binary.LittleEndian.PutUint16(rb, 9)
			if tok == nil {
				status = 0xC000006D
				break
			}
			switch binary.LittleEndian.Uint32(tok[8:]) {
			case 1:
				session = 0x1122334455
				ch := spnegoResp(f.ntlm.challenge(true))
				binary.LittleEndian.PutUint16(rb[4:], 72)
				binary.LittleEndian.PutUint16(rb[6:], uint16(len(ch)))
				rb = append(rb, ch...)
				status = statusMoreProcessing
			case 3:
				if !f.ntlm.verify(tok) {
					status = 0xC000006D
				} else {
					authed, key = true, f.ntlm.sessionKey
				}
			}
		case smb2TreeConnect:
			pl := int(binary.LittleEndian.Uint16(body[6:]))
			po := int(binary.LittleEndian.Uint16(body[4:])) - 64
			path := fromUTF16LE(body[po : po+pl])
			f.mu.Lock()
			f.treePaths = append(f.treePaths, path)
			f.mu.Unlock()
			name := path[strings.LastIndexByte(path, '\\')+1:]
			sh, ok := f.shares[name]
			rb = make([]byte, 16)
			binary.LittleEndian.PutUint16(rb, 16)
			if !ok {
				status = 0xC00000CC
			} else {
				share, treeID = sh, 7
			}
		case smb2Create:
			no := int(binary.LittleEndian.Uint16(body[44:])) - 64
			nl := int(binary.LittleEndian.Uint16(body[46:]))
			name := fromUTF16LE(body[no : no+nl])
			data, ok := share[name]
			rb = make([]byte, 89)
			binary.LittleEndian.PutUint16(rb, 89)
			if !ok {
				status = 0xC0000034
				break
			}
			id := uint64(len(files) + 1)
			files[id] = name
			binary.LittleEndian.PutUint64(rb[48:], uint64(len(data)))
			binary.LittleEndian.PutUint64(rb[64:], id)
		case smb2Read:
			ln := binary.LittleEndian.Uint32(body[4:])
			off := binary.LittleEndian.Uint64(body[8:])
			id := binary.LittleEndian.Uint64(body[16:])
			f.mu.Lock()
			f.readSizes = append(f.readSizes, ln)
			f.mu.Unlock()
			data := share[files[id]]
			rb = make([]byte, 17)
			binary.LittleEndian.PutUint16(rb, 17)
			if off >= uint64(len(data)) {
				status = statusEOF
				break
			}
			chunk := data[off:min(uint64(len(data)), off+uint64(ln))]
			rb[2] = 64 + 16
			binary.LittleEndian.PutUint32(rb[4:], uint32(len(chunk)))
			rb = append(rb[:16], chunk...)
		case smb2Close:
			rb = make([]byte, 60)
			binary.LittleEndian.PutUint16(rb, 60)
		default:
			rb = make([]byte, 4)
			binary.LittleEndian.PutUint16(rb, 4)
		}
		h := make([]byte, 64)
		copy(h, "\xfeSMB")
		binary.LittleEndian.PutUint16(h[4:], 64)
		binary.LittleEndian.PutUint32(h[8:], status)
		binary.LittleEndian.PutUint16(h[12:], cmd)
		binary.LittleEndian.PutUint16(h[14:], 1)
		binary.LittleEndian.PutUint32(h[16:], 1)
		copy(h[24:], msg[24:32])
		binary.LittleEndian.PutUint32(h[36:], treeID)
		binary.LittleEndian.PutUint64(h[40:], session)
		out := append(h, rb...)
		fr := make([]byte, 4)
		binary.BigEndian.PutUint32(fr, uint32(len(out)))
		c.Write(append(fr, out...))
	}
}

func TestSMBReadFileAndHash(t *testing.T) {
	content := strings.Repeat("0123456789", 100) // > 512 so the 512-then-rest read is exercised
	sum := sha256.Sum256([]byte(content))
	for _, signing := range []bool{false, true} {
		f := &fakeSMB{ntlm: &ntlmServer{users: map[string]string{"alice": "pw"}, targetName: "FILESRV"},
			shares: map[string]map[string][]byte{"data": {"report.txt": []byte(content)}}, signing: signing}
		h, p := f.start(t)
		spec := Spec{Type: SMB, Host: h, Port: p}
		good := cred("alice", "pw")
		it := Item{Share: "data", File: "report.txt", SHA256: hexOf(sum[:])}
		r := runOne(spec, &it, &good, Options{})
		if !r.OK {
			t.Fatalf("signing=%v: %+v", signing, r)
		}
		f.mu.Lock()
		if f.ntlm.gotDomain != "FILESRV" {
			t.Errorf("domain %q: bare user must authenticate against the server's own name", f.ntlm.gotDomain)
		}
		if len(f.treePaths) != 1 || f.treePaths[0] != `\\`+h+":"+portStr(p)+`\data` {
			t.Errorf("tree path %v must carry the port", f.treePaths)
		}
		if len(f.readSizes) < 2 || f.readSizes[0] != 512 {
			t.Errorf("reads %v: want 512 first then the rest", f.readSizes)
		}
		want := []uint16{smb2Negotiate, smb2SessionSetup, smb2SessionSetup, smb2TreeConnect, smb2Create, smb2Read, smb2Read, smb2Close, smb2TreeDisc, smb2Logoff}
		if len(f.cmds) != len(want) {
			t.Errorf("commands %v want %v", f.cmds, want)
		} else {
			for i := range want {
				if f.cmds[i] != want[i] {
					t.Errorf("commands %v want %v", f.cmds, want)
					break
				}
			}
		}
		if signing && (f.badSig != 0 || f.unsigned != 0) {
			t.Errorf("signing: %d bad, %d unsigned requests", f.badSig, f.unsigned)
		}
		if f.reqDialects[0] != 0x0202 {
			t.Errorf("dialects %v", f.reqDialects)
		}
		f.mu.Unlock()

		it.SHA256 = strings.Repeat("0", 64)
		if r = runOne(spec, &it, &good, Options{}); r.OK || r.Err != "file hash did not match" {
			t.Fatalf("%+v", r)
		}
		if r = runOne(spec, &Item{Share: "data", File: "report.txt", Regex: "0123456789$"}, &good, Options{}); !r.OK {
			t.Fatalf("%+v", r)
		}
		if r = runOne(spec, &Item{Share: "data", File: "nope.txt"}, &good, Options{}); r.OK {
			t.Fatalf("%+v", r)
		}
		if r = runOne(spec, &Item{Share: "missing", File: "x"}, &good, Options{}); r.OK || !strings.Contains(r.Err, "mount share") {
			t.Fatalf("%+v", r)
		}
		bad := cred("alice", "wrong")
		if r = runOne(spec, &it, &bad, Options{}); r.OK || r.Class != ClassAuth || !strings.Contains(r.Err, "smb login failed") {
			t.Fatalf("%+v", r)
		}
		if r = runOne(spec, nil, &good, Options{}); !r.OK { // login only
			t.Fatalf("%+v", r)
		}
	}
}

func hexOf(b []byte) string {
	const d = "0123456789abcdef"
	o := make([]byte, 0, 2*len(b))
	for _, c := range b {
		o = append(o, d[c>>4], d[c&15])
	}
	return string(o)
}
