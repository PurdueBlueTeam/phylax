package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// ErrWinRMAuth reports WinRM credentials the server refused.
var ErrWinRMAuth = errors.New("probe: winrm authentication refused")

const (
	winrmCommandAction = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command"
	winrmReceiveAction = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive"
	winrmDeleteAction  = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete"

	// A command's output is capped per stream so a chatty remote cannot
	// exhaust the controller's memory.
	winrmMaxStream = 1 << 20
	// Each Receive long-polls up to PT60S; an install can take minutes, so the
	// loop is generous but bounded.
	winrmReceiveLimit = 200
)

// WinRMConfig is one WinRM target. User is "user" or "DOMAIN\user"; Pass is
// the plaintext password (never logged by this client).
type WinRMConfig struct {
	Host string
	Port int // 5985 (http) or 5986 (https)
	TLS  bool
	User string
	Pass string
	Dial func(ctx context.Context, network, addr string) (net.Conn, error) // nil means a net.Dialer
}

// WinRMShell is an open WinRM shell that can run PowerShell scripts.
type WinRMShell struct {
	w     *winrmClient
	shell string
	url   string
}

// OpenWinRM connects with NTLM and creates a shell. TLS is the transport
// guarantee on 5986; on 5985 NTLM signing is requested, as the scorer-mimic
// probe does.
//
// shortcut: NTLM without message-level encryption on 5985 (the probe's
// behaviour), upgrade when a target requires AllowUnencrypted=false
// enforcement of sealing.
func OpenWinRM(ctx context.Context, c WinRMConfig) (*WinRMShell, error) {
	if c.Host == "" {
		return nil, errors.New("probe: winrm needs a host")
	}
	if c.Port <= 0 {
		c.Port = 5985
	}
	scheme := "http"
	if c.TLS {
		scheme = "https"
	}
	addr := net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
	dial := c.Dial
	if dial == nil {
		d := &net.Dialer{}
		dial = d.DialContext
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext:     dial,
		MaxConnsPerHost: 1, // NTLM authenticates the connection, not the request
	}
	user, domain := c.User, ""
	if i := strings.IndexByte(user, '\\'); i >= 0 {
		domain, user = user[:i], user[i+1:]
	}
	nc := &ntlmClient{user: user, pass: c.Pass, domain: domain,
		flags: ntlmUnicode | ntlmReqTarget | ntlmNTLM | ntlmExtSession | ntlm128 | ntlm56 | ntlmVersion | ntlmAlwaysSign}
	u := scheme + "://" + addr + "/wsman"
	w := &winrmClient{
		tr: tr,
		hc: &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}},
		url: u, nc: nc,
	}
	create := soapEnvelope(wsmanAction, wsmanShellURI, u, "",
		`<w:OptionSet><w:Option Name="WINRS_NOPROFILE">FALSE</w:Option><w:Option Name="WINRS_CODEPAGE">65001</w:Option></w:OptionSet>`,
		`<rsp:Shell><rsp:InputStreams>stdin</rsp:InputStreams><rsp:OutputStreams>stdout stderr</rsp:OutputStreams></rsp:Shell>`)
	resp, body, err := w.do(ctx, []byte(create))
	if err != nil {
		tr.CloseIdleConnections()
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		tr.CloseIdleConnections()
		return nil, ErrWinRMAuth
	}
	if resp.StatusCode != http.StatusOK {
		tr.CloseIdleConnections()
		return nil, fmt.Errorf("probe: winrm create shell: http %d", resp.StatusCode)
	}
	m := reShellID.FindSubmatch(body)
	if m == nil {
		m = reSelector.FindSubmatch(body)
	}
	if m == nil {
		tr.CloseIdleConnections()
		return nil, errors.New("probe: winrm create shell: no ShellId")
	}
	return &WinRMShell{w: w, shell: string(m[1]), url: u}, nil
}

// Run executes a PowerShell script (powershell.exe -EncodedCommand) and
// returns its output. A non-zero exit is reported in exit, not as an error;
// err is non-nil only for a transport or protocol failure.
func (s *WinRMShell) Run(ctx context.Context, script string) (stdout, stderr string, exit int, err error) {
	enc := base64.StdEncoding.EncodeToString(utf16le(script))
	cbody := `<rsp:CommandLine><rsp:Command>powershell.exe</rsp:Command><rsp:Arguments>-EncodedCommand</rsp:Arguments><rsp:Arguments>` + enc + `</rsp:Arguments></rsp:CommandLine>`
	resp, body, err := s.w.do(ctx, []byte(soapEnvelope(winrmCommandAction, wsmanShellURI, s.url, s.shell,
		`<w:OptionSet><w:Option Name="WINRS_CONSOLEMODE_STDIN">TRUE</w:Option><w:Option Name="WINRS_SKIP_CMD_SHELL">FALSE</w:Option></w:OptionSet>`, cbody)))
	if err != nil {
		return "", "", 0, err
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", 0, fmt.Errorf("probe: winrm command: http %d", resp.StatusCode)
	}
	cm := reCommandID.FindSubmatch(body)
	if cm == nil {
		return "", "", 0, errors.New("probe: winrm command: no CommandId")
	}
	cid := string(cm[1])
	var out, errOut cappedBuffer
	out.max, errOut.max = winrmMaxStream, winrmMaxStream
	done := false
	for range winrmReceiveLimit {
		rbody := `<rsp:Receive><rsp:DesiredStream CommandId="` + cid + `">stdout stderr</rsp:DesiredStream></rsp:Receive>`
		resp, body, err = s.w.do(ctx, []byte(soapEnvelope(winrmReceiveAction, wsmanShellURI, s.url, s.shell, "", rbody)))
		if err != nil {
			return "", "", 0, err
		}
		if resp.StatusCode != http.StatusOK {
			return "", "", 0, fmt.Errorf("probe: winrm receive: http %d", resp.StatusCode)
		}
		for _, st := range reStream.FindAllSubmatch(body, -1) {
			d, _ := base64.StdEncoding.DecodeString(string(st[2]))
			if string(st[1]) == "stdout" {
				_, _ = out.Write(d)
			} else {
				_, _ = errOut.Write(d)
			}
		}
		if e := reExit.FindSubmatch(body); e != nil {
			_, _ = fmt.Sscanf(string(e[1]), "%d", &exit)
		}
		if reDone.Match(body) {
			done = true
			break
		}
	}
	if !done {
		return "", "", 0, errors.New("probe: winrm command did not complete")
	}
	return out.String(), errOut.String(), exit, nil
}

// Close deletes the shell and closes idle connections.
func (s *WinRMShell) Close(ctx context.Context) error {
	del := soapEnvelope(winrmDeleteAction, wsmanShellURI, s.url, s.shell, "", "")
	resp, _, err := s.w.do(ctx, []byte(del))
	if s.w.tr != nil {
		s.w.tr.CloseIdleConnections()
	}
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("probe: winrm delete shell: http %d", resp.StatusCode)
	}
	return nil
}

// cappedBuffer keeps at most max bytes and discards the rest.
type cappedBuffer struct {
	max int
	b   bytes.Buffer
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.b.Len(); room > 0 {
		if len(p) > room {
			b.b.Write(p[:room])
		} else {
			b.b.Write(p)
		}
	}
	return len(p), nil
}

func (b *cappedBuffer) String() string { return b.b.String() }
