package probe

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

// A minimal SMB2 client: negotiate, NTLMv2 session setup (no domain), tree
// connect `\\<ip>:445\share`, open, read, close, tree disconnect, logoff. It
// offers dialects 2.0.2 and 2.1 only (no encryption, no pre-auth integrity),
// and signs requests with HMAC-SHA256 when the server requires signing.
const (
	smb2Negotiate    = 0
	smb2SessionSetup = 1
	smb2Logoff       = 2
	smb2TreeConnect  = 3
	smb2TreeDisc     = 4
	smb2Create       = 5
	smb2Close        = 6
	smb2Read         = 8

	statusMoreProcessing = 0xC0000016
	statusEOF            = 0xC0000011
	smb2FlagSigned       = 0x8
)

type smb2Conn struct {
	c       net.Conn
	msgID   uint64
	session uint64
	tree    uint32
	signKey []byte
	signing bool
	dialect uint16
}

func (s *smb2Conn) header(cmd uint16, bodyLen int) []byte {
	h := make([]byte, 64, 64+bodyLen)
	copy(h, "\xfeSMB")
	binary.LittleEndian.PutUint16(h[4:], 64)
	binary.LittleEndian.PutUint16(h[6:], 1) // credit charge
	binary.LittleEndian.PutUint16(h[12:], cmd)
	binary.LittleEndian.PutUint16(h[14:], 31) // credits requested
	binary.LittleEndian.PutUint64(h[24:], s.msgID)
	s.msgID++
	binary.LittleEndian.PutUint32(h[36:], s.tree)
	binary.LittleEndian.PutUint64(h[40:], s.session)
	return h
}

// roundTrip sends one request and returns (status, response header+body).
func (s *smb2Conn) roundTrip(cmd uint16, body []byte, sign bool) (uint32, []byte, error) {
	msg := append(s.header(cmd, len(body)), body...)
	if sign && s.signing && s.signKey != nil {
		binary.LittleEndian.PutUint32(msg[16:], binary.LittleEndian.Uint32(msg[16:])|smb2FlagSigned)
		mac := hmac.New(sha256.New, s.signKey)
		mac.Write(msg)
		copy(msg[48:64], mac.Sum(nil)[:16])
	}
	frame := make([]byte, 4, 4+len(msg))
	binary.BigEndian.PutUint32(frame, uint32(len(msg)))
	if _, err := s.c.Write(append(frame, msg...)); err != nil {
		return 0, nil, err
	}
	for {
		var l [4]byte
		if _, err := io.ReadFull(s.c, l[:]); err != nil {
			return 0, nil, err
		}
		n := int(binary.BigEndian.Uint32(l[:]) & 0xffffff)
		if n < 64 || n > 16<<20 {
			return 0, nil, fmt.Errorf("smb2: bad frame length %d", n)
		}
		resp := make([]byte, n)
		if _, err := io.ReadFull(s.c, resp); err != nil {
			return 0, nil, err
		}
		if string(resp[:4]) != "\xfeSMB" {
			return 0, nil, errors.New("smb2: bad protocol id")
		}
		// STATUS_PENDING interim responses: wait for the real one.
		st := binary.LittleEndian.Uint32(resp[8:])
		if st == 0x103 {
			continue
		}
		return st, resp, nil
	}
}

func (s *smb2Conn) negotiate() error {
	b := make([]byte, 36+4)
	binary.LittleEndian.PutUint16(b[0:], 36)
	binary.LittleEndian.PutUint16(b[2:], 2) // dialect count
	binary.LittleEndian.PutUint16(b[4:], 1) // signing enabled
	for i := range 16 {
		b[12+i] = byte(i*7 + 3) // client GUID
	}
	binary.LittleEndian.PutUint16(b[36:], 0x0202)
	binary.LittleEndian.PutUint16(b[38:], 0x0210)
	st, resp, err := s.roundTrip(smb2Negotiate, b, false)
	if err != nil {
		return err
	}
	if st != 0 || len(resp) < 64+64 {
		return fmt.Errorf("negotiate status 0x%x", st)
	}
	body := resp[64:]
	s.dialect = binary.LittleEndian.Uint16(body[4:])
	if s.dialect != 0x0202 && s.dialect != 0x0210 {
		return fmt.Errorf("server chose unsupported dialect 0x%x", s.dialect)
	}
	s.signing = binary.LittleEndian.Uint16(body[2:])&0x2 != 0 // signing required
	return nil
}

func (s *smb2Conn) sessionSetup(nc *ntlmClient) error {
	send := func(tok []byte, sign bool) (uint32, []byte, error) {
		b := make([]byte, 24, 24+len(tok))
		binary.LittleEndian.PutUint16(b[0:], 25)
		b[3] = 1 // security mode: signing enabled
		binary.LittleEndian.PutUint16(b[12:], 88)
		binary.LittleEndian.PutUint16(b[14:], uint16(len(tok)))
		return s.roundTrip(smb2SessionSetup, append(b, tok...), sign)
	}
	secBuffer := func(resp []byte) []byte {
		if len(resp) < 64+8 {
			return nil
		}
		off := int(binary.LittleEndian.Uint16(resp[64+4:]))
		l := int(binary.LittleEndian.Uint16(resp[64+6:]))
		if off+l > len(resp) {
			return nil
		}
		return resp[off : off+l]
	}
	st, resp, err := send(spnegoInit(nc.Negotiate()), false)
	if err != nil {
		return err
	}
	if st != statusMoreProcessing {
		return fmt.Errorf("session setup status 0x%x", st)
	}
	s.session = binary.LittleEndian.Uint64(resp[40:])
	chal := findNTLM(secBuffer(resp))
	if chal == nil {
		return errors.New("no NTLM challenge from the server")
	}
	auth, err := nc.Authenticate(chal)
	if err != nil {
		return err
	}
	st, _, err = send(spnegoResp(auth), false)
	if err != nil {
		return err
	}
	if st != 0 {
		return &smbLoginError{st}
	}
	s.signKey = nc.signingKey
	return nil
}

type smbLoginError struct{ status uint32 }

func (e *smbLoginError) Error() string { return fmt.Sprintf("session setup status 0x%x", e.status) }

func (s *smb2Conn) treeConnect(path string) error {
	pu := utf16le(path)
	b := make([]byte, 8, 8+len(pu))
	binary.LittleEndian.PutUint16(b[0:], 9)
	binary.LittleEndian.PutUint16(b[4:], 72)
	binary.LittleEndian.PutUint16(b[6:], uint16(len(pu)))
	st, resp, err := s.roundTrip(smb2TreeConnect, append(b, pu...), true)
	if err != nil {
		return err
	}
	if st != 0 {
		return fmt.Errorf("tree connect status 0x%x", st)
	}
	s.tree = binary.LittleEndian.Uint32(resp[36:])
	return nil
}

// open opens name for reading and returns the file id and size.
func (s *smb2Conn) open(name string) ([16]byte, uint64, error) {
	var fid [16]byte
	nu := utf16le(name)
	b := make([]byte, 56, 56+len(nu))
	binary.LittleEndian.PutUint16(b[0:], 57)
	binary.LittleEndian.PutUint32(b[4:], 2)         // impersonation
	binary.LittleEndian.PutUint32(b[24:], 0x120089) // read access
	binary.LittleEndian.PutUint32(b[32:], 7)        // share all
	binary.LittleEndian.PutUint32(b[36:], 1)        // FILE_OPEN
	binary.LittleEndian.PutUint32(b[40:], 0x40)     // non-directory
	binary.LittleEndian.PutUint16(b[44:], 120)      // name offset
	binary.LittleEndian.PutUint16(b[46:], uint16(len(nu)))
	st, resp, err := s.roundTrip(smb2Create, append(b, nu...), true)
	if err != nil {
		return fid, 0, err
	}
	if st != 0 || len(resp) < 64+80 {
		return fid, 0, fmt.Errorf("create status 0x%x", st)
	}
	body := resp[64:]
	size := binary.LittleEndian.Uint64(body[48:])
	copy(fid[:], body[64:80])
	return fid, size, nil
}

func (s *smb2Conn) read(fid [16]byte, off uint64, n uint32) ([]byte, error) {
	b := make([]byte, 49)
	binary.LittleEndian.PutUint16(b[0:], 49)
	binary.LittleEndian.PutUint32(b[4:], n)
	binary.LittleEndian.PutUint64(b[8:], off)
	copy(b[16:], fid[:])
	st, resp, err := s.roundTrip(smb2Read, b, true)
	if err != nil {
		return nil, err
	}
	if st == statusEOF {
		return nil, io.EOF
	}
	if st != 0 || len(resp) < 64+16 {
		return nil, fmt.Errorf("read status 0x%x", st)
	}
	dOff := int(resp[64+2])
	dLen := int(binary.LittleEndian.Uint32(resp[64+4:]))
	if dOff+dLen > len(resp) {
		return nil, errors.New("read: bad data offset")
	}
	return resp[dOff : dOff+dLen], nil
}

func (s *smb2Conn) simple(cmd uint16, size uint16, fid *[16]byte) {
	var b []byte
	if fid != nil {
		b = make([]byte, 24)
		copy(b[8:], fid[:])
	} else {
		b = make([]byte, 4)
	}
	binary.LittleEndian.PutUint16(b[0:], size)
	_, _, _ = s.roundTrip(cmd, b, true)
}

func probeSMB(ctx context.Context, p *probe) error {
	user, pass := "guest", ""
	if p.hasCr {
		user, pass = p.cred.User, p.cred.Pass.Reveal()
	}
	c, err := p.dialSpec(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	p.step("connect")
	s := &smb2Conn{c: c}
	if err := s.negotiate(); err != nil {
		return protoErr(err, "smb negotiate failed")
	}
	p.step("negotiate")
	// NTLM with no domain: the client takes the server's own name from the
	// challenge, so a bare user hits the local account database of a member server.
	nc := &ntlmClient{user: user, pass: pass, useServerTarget: true}
	if err := s.sessionSetup(nc); err != nil {
		var le *smbLoginError
		if errors.As(err, &le) {
			return failDebug(ClassAuth, err.Error(), "smb login failed: creds %s", user)
		}
		return protoErr(err, "smb login failed")
	}
	p.step("session")
	if p.item.Share == "" && p.item.File == "" {
		s.simple(smb2Logoff, 4, nil)
		return nil
	}
	// The tree path carries the port: \\<ip>:445\share, as the scorer's does.
	path := `\\` + p.spec.Host + ":" + strconv.Itoa(p.spec.port()) + `\` + p.item.Share
	if err := s.treeConnect(path); err != nil {
		return failDebug(ClassProtocol, err.Error(), "failed to mount share %s", p.item.Share)
	}
	p.step("tree")
	if p.item.File == "" {
		s.simple(smb2TreeDisc, 4, nil)
		s.simple(smb2Logoff, 4, nil)
		return nil
	}
	fid, size, err := s.open(p.item.File)
	if err != nil {
		return failDebug(ClassContent, err.Error(), "failed to open file %s", p.item.File)
	}
	var data []byte
	first := uint32(512)
	if uint64(first) > size {
		first = uint32(size)
	}
	if first > 0 {
		d, err := s.read(fid, 0, first)
		if err != nil && err != io.EOF {
			return failDebug(ClassContent, err.Error(), "failed to read file %s", p.item.File)
		}
		data = append(data, d...)
	}
	for uint64(len(data)) < size && len(data) < maxBody {
		n := uint32(min(size-uint64(len(data)), 60000))
		d, err := s.read(fid, uint64(len(data)), n)
		if err == io.EOF || (err == nil && len(d) == 0) {
			break
		}
		if err != nil {
			return failDebug(ClassContent, err.Error(), "failed to read file %s", p.item.File)
		}
		data = append(data, d...)
	}
	p.step("read")
	s.simple(smb2Close, 24, &fid)
	s.simple(smb2TreeDisc, 4, nil)
	s.simple(smb2Logoff, 4, nil)
	return checkFile(p, data, p.item.File)
}
