package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
)

// WinRM over NTLM, like masterzen/winrm with the go-ntlmssp negotiator: the
// SOAP create-shell is POSTed to /wsman with no Authorization first; on a 401
// offering Negotiate/NTLM the negotiator sends the NTLM NEGOTIATE (empty body),
// then the AUTHENTICATE with the original body, all on one connection. The
// domain is whatever the user string carries; a bare user means no domain.

const (
	wsmanShellURI = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd"
	wsmanAction   = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create"
)

func soapEnvelope(action, resourceURI, to, shellID string, opts, body string) string {
	sel := ""
	if shellID != "" {
		sel = `<w:SelectorSet><w:Selector Name="ShellId">` + shellID + `</w:Selector></w:SelectorSet>`
	}
	return `<?xml version="1.0" encoding="UTF-8"?><env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope" ` +
		`xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" ` +
		`xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">` +
		`<env:Header><a:To>` + to + `</a:To><w:ResourceURI env:mustUnderstand="true">` + resourceURI + `</w:ResourceURI>` +
		`<a:ReplyTo><a:Address env:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>` +
		`<a:Action env:mustUnderstand="true">` + action + `</a:Action><w:MaxEnvelopeSize env:mustUnderstand="true">153600</w:MaxEnvelopeSize>` +
		`<a:MessageID>uuid:` + fmt.Sprintf("%016x", len(body)) + `</a:MessageID><w:Locale xml:lang="en-US" env:mustUnderstand="false"/>` +
		`<w:OperationTimeout>PT60S</w:OperationTimeout>` + sel + opts + `</env:Header><env:Body>` + body + `</env:Body></env:Envelope>`
}

type winrmClient struct {
	p    *probe
	hc   *http.Client
	tr   *http.Transport
	url  string
	nc   *ntlmClient
	auth string // negotiated Authorization header for this connection, once authenticated
}

func (w *winrmClient) do(ctx context.Context, body []byte) (*http.Response, []byte, error) {
	newReq := func(b []byte) (*http.Request, error) {
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		r.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
		r.Header.Set("User-Agent", "Go-http-client/1.1")
		return r, nil
	}
	read := func(r *http.Response) ([]byte, error) {
		defer r.Body.Close()
		return io.ReadAll(io.LimitReader(r.Body, maxBody))
	}
	r, err := newReq(body)
	if err != nil {
		return nil, nil, err
	}
	if w.auth != "" {
		r.Header.Set("Authorization", w.auth)
	}
	resp, err := w.hc.Do(r)
	if err != nil {
		return nil, nil, err
	}
	b, err := read(resp)
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized || w.auth != "" {
		return resp, b, nil
	}
	scheme := ""
	for _, h := range resp.Header.Values("Www-Authenticate") {
		for _, s := range []string{"Negotiate", "NTLM"} {
			if strings.HasPrefix(strings.TrimSpace(h), s) && scheme == "" {
				scheme = s
			}
		}
	}
	if scheme == "" {
		return resp, b, nil
	}
	r, _ = newReq(nil)
	r.Header.Set("Authorization", scheme+" "+base64.StdEncoding.EncodeToString(w.nc.Negotiate()))
	resp, err = w.hc.Do(r)
	if err != nil {
		return nil, nil, err
	}
	b, err = read(resp)
	if err != nil {
		return nil, nil, err
	}
	var chal []byte
	for _, h := range resp.Header.Values("Www-Authenticate") {
		if f := strings.Fields(h); len(f) == 2 && strings.EqualFold(f[0], scheme) {
			chal, _ = base64.StdEncoding.DecodeString(f[1])
		}
	}
	if chal = findNTLM(chal); chal == nil {
		return resp, b, nil // 401 without a challenge: credentials refused outright
	}
	am, err := w.nc.Authenticate(chal)
	if err != nil {
		return nil, nil, err
	}
	w.auth = scheme + " " + base64.StdEncoding.EncodeToString(am)
	r, _ = newReq(body)
	r.Header.Set("Authorization", w.auth)
	resp, err = w.hc.Do(r)
	if err != nil {
		return nil, nil, err
	}
	b, err = read(resp)
	return resp, b, err
}

var (
	reShellID   = regexp.MustCompile(`<[a-z]*:?ShellId>([^<]+)<`)
	reSelector  = regexp.MustCompile(`Name="ShellId"[^>]*>([^<]+)<`)
	reCommandID = regexp.MustCompile(`<[a-z]*:?CommandId>([^<]+)<`)
	reStream    = regexp.MustCompile(`<[a-z]*:?Stream[^>]*Name="(stdout|stderr)"[^>]*>([^<]*)<`)
	reExit      = regexp.MustCompile(`<[a-z]*:?ExitCode>(-?\d+)<`)
	reDone      = regexp.MustCompile(`CommandState[^>]*State="[^"]*/Done"`)
)

func probeWinRM(ctx context.Context, p *probe) error {
	if err := p.needCred(); err != nil {
		return err
	}
	scheme := "http"
	if p.spec.Encrypted {
		scheme = "https"
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return p.dial(ctx, network, addr)
		},
		MaxConnsPerHost: 1, // NTLM authenticates the connection, not the request
	}
	defer tr.CloseIdleConnections()
	user, domain := p.cred.User, ""
	if i := strings.IndexByte(user, '\\'); i >= 0 {
		domain, user = user[:i], user[i+1:]
	}
	nc := &ntlmClient{user: user, pass: p.cred.Pass.Reveal(), domain: domain, flags: ntlmUnicode | ntlmReqTarget | ntlmNTLM | ntlmExtSession | ntlm128 | ntlm56 | ntlmVersion | ntlmAlwaysSign}
	w := &winrmClient{p: p, tr: tr, hc: &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, url: scheme + "://" + p.spec.addr() + "/wsman", nc: nc}
	cmd := p.item.Command
	if cmd == "" {
		cmd = "hostname"
	}
	to := w.url
	create := soapEnvelope(wsmanAction, wsmanShellURI, to, "", `<w:OptionSet><w:Option Name="WINRS_NOPROFILE">FALSE</w:Option><w:Option Name="WINRS_CODEPAGE">65001</w:Option></w:OptionSet>`,
		`<rsp:Shell><rsp:InputStreams>stdin</rsp:InputStreams><rsp:OutputStreams>stdout stderr</rsp:OutputStreams></rsp:Shell>`)
	resp, body, err := w.do(ctx, []byte(create))
	if err != nil {
		return classify(err, "error creating winrm client")
	}
	p.step("auth")
	if resp.StatusCode == http.StatusUnauthorized {
		return failDebug(ClassAuth, resp.Status, "connection test failed with creds %s: http response error: 401", p.cred.User)
	}
	if resp.StatusCode != 200 {
		return failDebug(ClassProtocol, string(body), "http response error: %d", resp.StatusCode)
	}
	m := reShellID.FindSubmatch(body)
	if m == nil {
		m = reSelector.FindSubmatch(body)
	}
	if m == nil {
		return failDebug(ClassProtocol, string(body), "no ShellId in the create response")
	}
	shell := string(m[1])
	defer func() {
		del := soapEnvelope("http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete", wsmanShellURI, to, shell, "", "")
		dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*p.opts.timeout()/8+1)
		defer cancel()
		_, _, _ = w.do(dctx, []byte(del))
	}()
	// powershell.exe -EncodedCommand <utf16le base64>, as masterzen's Powershell wrapper does
	enc := base64.StdEncoding.EncodeToString(utf16le(cmd))
	cbody := `<rsp:CommandLine><rsp:Command>powershell.exe</rsp:Command><rsp:Arguments>-EncodedCommand</rsp:Arguments><rsp:Arguments>` + enc + `</rsp:Arguments></rsp:CommandLine>`
	resp, body, err = w.do(ctx, []byte(soapEnvelope("http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command", wsmanShellURI, to, shell,
		`<w:OptionSet><w:Option Name="WINRS_CONSOLEMODE_STDIN">TRUE</w:Option><w:Option Name="WINRS_SKIP_CMD_SHELL">FALSE</w:Option></w:OptionSet>`, cbody)))
	if err != nil {
		return classify(err, "command failed")
	}
	cm := reCommandID.FindSubmatch(body)
	if resp.StatusCode != 200 || cm == nil {
		return failDebug(ClassProtocol, string(body), "starting the command failed")
	}
	cid := string(cm[1])
	p.step("command")
	var out, errOut bytes.Buffer
	exit, done := 0, false
	for range 20 {
		rbody := `<rsp:Receive><rsp:DesiredStream CommandId="` + cid + `">stdout stderr</rsp:DesiredStream></rsp:Receive>`
		resp, body, err = w.do(ctx, []byte(soapEnvelope("http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive", wsmanShellURI, to, shell, "", rbody)))
		if err != nil {
			return classify(err, "command failed")
		}
		if resp.StatusCode != 200 {
			return failDebug(ClassProtocol, string(body), "receive failed")
		}
		for _, s := range reStream.FindAllSubmatch(body, -1) {
			d, _ := base64.StdEncoding.DecodeString(string(s[2]))
			if string(s[1]) == "stdout" {
				out.Write(d)
			} else {
				errOut.Write(d)
			}
		}
		if e := reExit.FindSubmatch(body); e != nil {
			fmt.Sscanf(string(e[1]), "%d", &exit)
		}
		if reDone.Match(body) {
			done = true
			break
		}
	}
	p.step("receive")
	if !done {
		return fail(ClassTimeout, "command did not complete")
	}
	// Any stderr fails, as in the scorer.
	if errOut.Len() > 0 {
		return failDebug(ClassContent, errOut.String(), "command wrote to stderr")
	}
	got := strings.TrimSpace(out.String())
	if p.item.Output != "" {
		if p.item.UseRegex {
			re, err := regexp.Compile(p.item.Output)
			if err != nil {
				return fail(ClassConfig, "bad regex: %v", err)
			}
			if !re.MatchString(got) {
				return failDebug(ClassContent, got, "command output didn't match regex")
			}
		} else if got != strings.TrimSpace(p.item.Output) {
			return failDebug(ClassContent, got, "command output didn't match string")
		}
	}
	if p.strict() {
		if exit != 0 {
			p.strictIssue("exit code %d", exit)
		}
		if got == "" {
			p.strictIssue("command produced no output")
		}
	}
	return nil
}
