package controller

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/link"
)

// BootstrapConfig is what /bootstrap.json returns: everything the console
// one-liner needs to install and enroll the host.
type BootstrapConfig struct {
	Controller string   `json:"controller"` // addr:port the agent dials
	Pin        link.Pin `json:"pin"`
	Host       string   `json:"host"`
	Token      string   `json:"token"`
	Roles      []string `json:"roles"`
	BinarySHA  string   `json:"binary_sha256"`
	PlanKey    string   `json:"plan_key,omitempty"` // base64 ed25519 public key
}

// handleBootstrap serves plain-HTTPS connections (no phylax ALPN): the
func (c *Controller) handleBootstrap(conn *tls.Conn) {
	// The http server owns conn from here; IdleTimeout bounds keep-alive.
	srv := &http.Server{
		Handler: c.bootstrapMux(), ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout: 30 * time.Second,
	}
	srv.Serve(&onceListener{c: conn})
}

// onceListener hands a single pre-established connection to an http.Server.
type onceListener struct{ c net.Conn }

func (l *onceListener) Accept() (net.Conn, error) {
	c := l.c
	l.c = nil
	if c == nil {
		return nil, net.ErrClosed
	}
	return c, nil
}

func (l *onceListener) Close() error { return net.ErrClosed }

func (l *onceListener) Addr() net.Addr {
	if l.c != nil {
		return l.c.LocalAddr()
	}
	return nil
}

func (c *Controller) bootstrapMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/phylax", c.handleDownloadBinary)
	mux.HandleFunc("/bootstrap.json", c.handleBootstrapJSON)
	mux.HandleFunc("/platform", c.handlePlatform)
	mux.HandleFunc("/token", c.handleToken)
	mux.HandleFunc("/plan/run", c.handlePlanRun)
	mux.HandleFunc("/plan/status", c.handlePlanStatus)
	mux.HandleFunc("/plan/dag", c.handlePlanDAG)
	mux.HandleFunc("/alerts", c.handleAlerts)
	mux.HandleFunc("/alerts/respond", c.handleRespond)
	return mux
}

// checkToken validates (without consuming) a bootstrap token for a host.
func (c *Controller) checkToken(token, host string) bool {
	if host == "" || token == "" {
		return false
	}
	tok, expires, used, err := c.st.TokenInfo(token)
	return err == nil && used == 0 && !time.Now().UTC().After(expires) && tok == host
}

func (c *Controller) handleDownloadBinary(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if !c.checkToken(q.Get("token"), q.Get("host")) {
		http.Error(w, "bad token", http.StatusForbidden)
		return
	}
	if c.binary == nil {
		http.Error(w, "no binary configured", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(c.binary)
}

func (c *Controller) handleBootstrapJSON(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	host, token := q.Get("host"), q.Get("token")
	if !c.checkToken(token, host) {
		http.Error(w, "bad token", http.StatusForbidden)
		return
	}
	roles, _ := c.hostRoles(host)
	cfg := BootstrapConfig{
		Controller: c.serveAddr(),
		Pin:        c.pin,
		Host:       host,
		Token:      token,
		Roles:      roles,
		BinarySHA:  c.BinarySHA256Hex(),
		PlanKey:    c.PlanKeyPub(),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(cfg)
}

// serveAddr is the address agents should dial.
func (c *Controller) serveAddr() string {
	if c.advertise != "" {
		return c.advertise
	}
	if c.ln != nil {
		return c.ln.Addr().String()
	}
	return "127.0.0.1:7443"
}

// SetAdvertise overrides the address reported in bootstrap configs (used
// when the listener address is not the dialable one, e.g. tests and NAT).
func (c *Controller) SetAdvertise(addr string) { c.advertise = addr }

func (c *Controller) hostRoles(host string) ([]string, error) {
	h, err := c.st.GetHost(host)
	if err != nil {
		return nil, err
	}
	return h.Roles, nil
}

func (c *Controller) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	host := r.URL.Query().Get("host")
	if host == "" {
		http.Error(w, "host required", http.StatusBadRequest)
		return
	}
	tok, err := c.st.IssueToken(host, 10*time.Minute)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(w, `{"token":%q,"host":%q,"console":%q}`,
		tok, host, consoleCommand(c.serveAddr(), c.pin, host, tok, c.BinarySHA256Hex()))
}

// consoleCommand renders the human operator one-liner for a host. The
// pinned key is checked by the TLS stack BEFORE the token is ever sent, so
// a wrong controller key aborts with a TLS error, not an enrollment.
func consoleCommand(addr string, pin link.Pin, host, token, sha string) string {
	pk := "sha256//" + string(pin)
	return fmt.Sprintf(
		`curl --proto '=https' --tlsv1.2 --pinnedpubkey %s -o /tmp/phylax "%s/phylax?host=%s&token=%s" && `+
			`echo "%s  /tmp/phylax" | sha256sum -c - && install -m 755 /tmp/phylax /opt/phylax/phylax && `+
			`curl --pinnedpubkey %s -o /opt/phylax/bootstrap.json "%s/bootstrap.json?host=%s&token=%s"`,
		pk, addr, host, token, sha, pk, addr, host, token)
}

// handlePlatform renders the platform overview page (self-health, M1).
func (c *Controller) handlePlatform(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<html><head><title>phylax platform</title>`+
		`<meta http-equiv="refresh" content="5"></head><body>`+
		`<h1>Phylax platform</h1><table border="1" cellpadding="4">`+
		`<tr><th>host</th><th>status</th><th>last heartbeat</th><th>spool tip</th><th>events</th></tr>`)
	hs, _ := c.st.ListHosts()
	darkCutoff := time.Now().Add(-c.darkAfter)
	for _, h := range hs {
		status := h.Status
		if h.Status == "enrolled" && !h.LastHeartbeat.IsZero() && h.LastHeartbeat.Before(darkCutoff) {
			status = "dark"
		}
		n, _ := c.st.EventCount(h.Name)
		_, _ = fmt.Fprintf(w, `<tr><td>%s</td><td>%s</td><td>%s</td><td>%d</td><td>%d</td></tr>`,
			esc(h.Name), esc(status), esc(h.LastHeartbeat.Format(time.RFC3339)), h.ChainSeq, n)
	}
	fmt.Fprint(w, `</table></body></html>`)
}

func esc(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}
