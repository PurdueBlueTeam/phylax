package probe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
)

// A minimal LDAPv3 simple bind (BER by hand): bind as user@domain with the
// password, cleartext on 389, TLS without verification on 636.

func berInt(v int) []byte {
	b := []byte{byte(v)}
	if v > 127 {
		b = []byte{0, byte(v)}
	}
	return der(0x02, b)
}

func ldapBindRequest(msgID int, dn, pass string) []byte {
	bind := der(0x60, berInt(3), der(0x04, []byte(dn)), der(0x80, []byte(pass)))
	return der(0x30, berInt(msgID), bind)
}

// readBER reads one TLV and returns tag and value.
func readBER(r io.Reader) (byte, []byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, nil, err
	}
	n := int(h[1])
	if n&0x80 != 0 {
		k := n & 0x7f
		if k == 0 || k > 3 {
			return 0, nil, errors.New("ber: unsupported length")
		}
		lb := make([]byte, k)
		if _, err := io.ReadFull(r, lb); err != nil {
			return 0, nil, err
		}
		n = 0
		for _, c := range lb {
			n = n<<8 | int(c)
		}
	}
	if n > 1<<20 {
		return 0, nil, errors.New("ber: too long")
	}
	v := make([]byte, n)
	if _, err := io.ReadFull(r, v); err != nil {
		return 0, nil, err
	}
	return h[0], v, nil
}

type bytesReader struct{ b []byte }

func (r *bytesReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}

func probeLDAP(ctx context.Context, p *probe) error {
	if err := p.needCred(); err != nil {
		return err
	}
	var c net.Conn
	c, err := p.dialSpec(ctx)
	if err != nil {
		return failDebug(ClassUnreachable, "", "failed to connect")
	}
	if p.spec.Encrypted {
		if c, err = p.tlsClient(ctx, c, false); err != nil {
			return err
		}
	}
	defer c.Close()
	p.step("connect")
	dn := p.userAt()
	if _, err := c.Write(ldapBindRequest(1, dn, p.cred.Pass.Reveal())); err != nil {
		return protoErr(err, "failed to connect")
	}
	tag, v, err := readBER(c)
	if err != nil || tag != 0x30 {
		return protoErr(errors.Join(err, fmt.Errorf("tag 0x%x", tag)), "failed to read bind response")
	}
	br := &bytesReader{v}
	if _, _, err = readBER(br); err != nil { // message id
		return protoErr(err, "bad bind response")
	}
	tag, op, err := readBER(br)
	if err != nil || tag != 0x61 {
		return fail(ClassProtocol, "unexpected LDAP response 0x%x", tag)
	}
	ir := &bytesReader{op}
	_, code, err := readBER(ir)
	if err != nil || len(code) == 0 {
		return fail(ClassProtocol, "bad bind result")
	}
	_, _, _ = readBER(ir)
	_, diag, _ := readBER(ir)
	p.step("bind")
	if code[len(code)-1] != 0 {
		return failDebug(ClassAuth, fmt.Sprintf("resultCode %d %s", code[len(code)-1], diag), "login failed for %s", p.cred.User)
	}
	if p.strict() && p.cred.Pass.IsZero() {
		p.strictIssue("empty password: a success is an unauthenticated bind, not a login")
	}
	_, _ = c.Write(der(0x30, berInt(2), der(0x42, nil))) // unbind
	return nil
}
