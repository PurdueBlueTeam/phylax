package controller

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

// ---- plan execution (M2) --------------------------------------------------------

// plans.go owns the plan-signing key, the per-host executor registry and
// the plan endpoints on the console API.

const (
	planEpoch = 1 // bumped on controller restore; steps carry it
)

func (c *Controller) loadOrCreatePlanKey() error {
	keyPath := filepath.Join(c.st.Dir(), "plan.key")
	if b, err := os.ReadFile(keyPath); err == nil && len(b) >= ed25519.SeedSize {
		// stored as the 32-byte seed (ed25519.PrivateKey is seed||pub; the
		// cache key is a pointer into the slice, so it must outlive Sign)
		c.planKey = ed25519.NewKeyFromSeed(b[:ed25519.SeedSize])
	} else {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		c.planKey = priv
		if err := os.WriteFile(keyPath, priv.Seed(), 0o600); err != nil {
			return err
		}
	}
	c.planKeyPub = base64.StdEncoding.EncodeToString(c.planKey.Public().(ed25519.PublicKey))
	return nil
}

// nextSeq is the plan-step sequence counter (per controller, not per host:
// the agent's spool watermark is a separate namespace).
func (c *Controller) nextSeq() uint64 {
	c.seqMu.Lock()
	defer c.seqMu.Unlock()
	c.seq++
	return c.seq
}

// PlanKeyPub is the base64 plan-signing public key for bootstrap bundles.
func (c *Controller) PlanKeyPub() string { return c.planKeyPub }

func (c *Controller) signStep(st *link.Step) {
	can := plan.Canonical(st.Plan, st.Node, st.Epoch, st.Seq, st.Op, st.Phase, st.Action, st.Params)
	if c.planKey == nil {
		st.Sig = "" // no plan key: agent will reject; operator error, logged
		c.log.Printf("ALERT: plan key missing; step unsigned")
		return
	}
	sig := ed25519.Sign(c.planKey, []byte(can))
	st.Sig = base64.StdEncoding.EncodeToString(sig)
}

// RunPlan starts a plan on one host. Only one plan runs per host at a time.
func (c *Controller) RunPlan(host string, p *plan.Plan, dryRun bool) (*plan.Exec, error) {
	c.plansMu.Lock()
	defer c.plansMu.Unlock()
	if ex, ok := c.plans[host]; ok {
		if st := ex.Status().State; st != plan.PStSuccess && st != plan.PStDryRun &&
			st != plan.PStFailed && st != plan.PStRolledBack {
			return nil, fmt.Errorf("host %s already running plan %q (%s)", host, c.planName[host], st)
		}
	}
	ex := plan.New(host, p, c.dispatchStep, c.Logf, planEpoch)
	if err := ex.Start(c.ctx, dryRun); err != nil {
		return nil, err
	}
	c.plans[host] = ex
	c.log.Printf("plan %s on %s started (dry=%v)", p.Name, host, dryRun)
	return ex, nil
}
// dispatchStep signs and sends one step to the host.
func (c *Controller) dispatchStep(host string, s plan.Step) error {
	c.connsMu.Lock()
	ac, ok := c.conns[host]
	c.connsMu.Unlock()
	if !ok {
		return fmt.Errorf("host %s not connected", host)
	}
	st := &link.Step{
		Plan:    s.Plan,
		Node:    s.Node,
		Epoch:   planEpoch,
		Seq:     c.nextSeq(),
		Op:      string(s.Op),
		Phase:   string(s.Phase),
		Action:  s.Action,
		Params:  s.Params,
		Before:  s.Before,
		Deadman: s.Deadman,
	}
	c.signStep(st)
	return ac.sendStep(st)
}

// setHostSafeMode records a host's safe-mode flag from its heartbeat.
func (c *Controller) setHostSafeMode(host string, on bool) {
	c.safeMu.Lock()
	defer c.safeMu.Unlock()
	c.safeModes[host] = on
}

// StepResultIn feeds an agent step outcome into the host's executor.
func (c *Controller) StepResultIn(host string, sr link.StepResult) {
	c.plansMu.Lock()
	ex, ok := c.plans[host]
	c.plansMu.Unlock()
	if !ok {
		return
	}
	ex.Result(sr.Node, plan.Result{
		OK:     sr.OK,
		Done:   sr.Done,
		Detail: sr.Detail,
		Before: sr.Before,
	})
}

// hostGone tells the host's executor the link dropped.
func (c *Controller) hostGone(host string) {
	c.plansMu.Lock()
	ex, ok := c.plans[host]
	c.plansMu.Unlock()
	if ok {
		ex.HostGone()
	}
}

// hostBack tells the host's executor the link is restored.
func (c *Controller) hostBack(host string) {
	c.plansMu.Lock()
	ex, ok := c.plans[host]
	c.plansMu.Unlock()
	if ok {
		ex.HostBack()
	}
}

// HostStatus is the display state of a host's plan (console API).
type HostStatus struct {
	Host     string               `json:"host"`
	Plan     string               `json:"plan,omitempty"`
	State    string               `json:"state,omitempty"`
	Nodes    map[string]NodeJSON  `json:"nodes,omitempty"`
	Rollback []string             `json:"rollback,omitempty"`
}

// NodeJSON is one node's display state.
type NodeJSON struct {
	Action  string `json:"action"`
	State   string `json:"state"`
	Diff    string `json:"diff,omitempty"`
	Failure string `json:"failure,omitempty"`
}

// PlansStatus returns the execution state of every tracked plan.
func (c *Controller) PlansStatus() []HostStatus {
	c.plansMu.Lock()
	defer c.plansMu.Unlock()
	var out []HostStatus
	for host, ex := range c.plans {
		s := ex.Status()
		hs := HostStatus{Host: host, State: string(s.State), Plan: c.planName[host]}
		hs.Nodes = map[string]NodeJSON{}
		for id, n := range s.Nodes {
			hs.Nodes[id] = NodeJSON{Action: n.Action, State: string(n.State),
				Diff: n.Diff, Failure: n.Failure}
		}
		hs.Rollback = s.Rollback
		out = append(out, hs)
	}
	return out
}

// ---- console plan endpoints (localhost only) -----------------------------------

// PlanRunRequest is the POST /plan/run body.
type PlanRunRequest struct {
	Host string `json:"host"`
	Dry  bool   `json:"dry"`
	Plan []byte `json:"plan"` // plan document (JSON or YAML)
}

func (c *Controller) handlePlanRun(w http.ResponseWriter, r *http.Request) {
	if !isLoopback(r.RemoteAddr) {
		http.Error(w, "localhost only", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req PlanRunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	p, err := plan.Load(req.Plan)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := c.RunPlan(req.Host, p, req.Dry); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusAccepted)
	fmt.Fprintf(w, `{"plan":%q,"host":%q,"dry":%v}`, p.Name, req.Host, req.Dry)
}

func (c *Controller) handlePlanStatus(w http.ResponseWriter, r *http.Request) {
	if !isLoopback(r.RemoteAddr) {
		http.Error(w, "localhost only", http.StatusForbidden)
		return
	}
	json.NewEncoder(w).Encode(c.PlansStatus())
}

func (c *Controller) handlePlanDAG(w http.ResponseWriter, r *http.Request) {
	if !isLoopback(r.RemoteAddr) {
		http.Error(w, "localhost only", http.StatusForbidden)
		return
	}
	// body: the plan document; response: an SVG of its DAG
	body := make([]byte, 0)
	buf := make([]byte, 4096)
	for {
		n, err := r.Body.Read(buf)
		body = append(body, buf[:n]...)
		if err != nil {
			break
		}
	}
	p, err := plan.Load(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Write(PlanDAGSVG(p))
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// PlanDAGSVG renders a plan as an SVG (docs: DAG in the UI, layout in Go).
func PlanDAGSVG(p *plan.Plan) []byte {
	cols := map[string]int{}
	for _, n := range p.Nodes {
		depth := 0
		for _, d := range n.Depends {
			if c := cols[d]; c >= depth {
				depth = c + 1
			}
		}
		cols[n.ID] = depth
	}
	width := 0
	for _, d := range cols {
		if d >= width {
			width = d + 1
		}
	}
	const (
		cw, chh = 180, 44
		gx, gy  = 60, 40
	)
	pos := map[string][2]int{}
	rows := map[int][]string{}
	for id, d := range cols {
		rows[d] = append(rows[d], id)
		pos[id] = [2]int{d, len(rows[d]) - 1}
	}
	w := width*(cw+gx) + gx
	h := 0
	for _, r := range rows {
		if len(r) > h {
			h = len(r)
		}
	}
	h = h*(chh+gy) + gy
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" font-family="monospace" font-size="13">`, w, h)
	// edges first (under the boxes)
	for _, n := range p.Nodes {
		for _, d := range n.Depends {
			a, okA := pos[d]
			bb, okB := pos[n.ID]
			if !okA || !okB {
				continue
			}
			x1 := a[0]*(cw+gx) + gx + cw
			y1 := a[1]*(chh+gy) + gy + chh/2
			x2 := bb[0]*(cw+gx) + gx
			y2 := bb[1]*(chh+gy) + gy + chh/2
			fmt.Fprintf(&b, `<path d="M %d %d C %d %d, %d %d, %d %d" fill="none" stroke="#888" stroke-width="1.5"/>`,
				x1, y1, (x1+x2)/2, y1, (x1+x2)/2, y2, x2, y2)
		}
	}
	for _, n := range p.Nodes {
		p2 := pos[n.ID]
		px, py := p2[0]*(cw+gx)+gx, p2[1]*(chh+gy)+gy
		fmt.Fprintf(&b, `<rect x="%d" y="%d" width="%d" height="%d" rx="6" fill="none" stroke="#555"/>`, px, py, cw, chh)
		fmt.Fprintf(&b, `<text x="%d" y="%d">%s</text>`, px+10, py+18, esc(n.ID))
		fmt.Fprintf(&b, `<text x="%d" y="%d" fill="#888">%s</text>`, px+10, py+35, esc(n.Action))
	}
	b.WriteString("</svg>")
	return []byte(b.String())
}
