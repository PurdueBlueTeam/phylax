package controller

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

// ---- alerts and one-click responses --------------------------------------------

// AlertView is one stored alert (or response/incident) for the UI.
type AlertView struct {
	Seq    uint64       `json:"seq"`
	TS     string       `json:"ts"`
	Host   string       `json:"host"`
	Type   string       `json:"type"` // alert | response | incident
	Data   map[string]any `json:"data"`
	Hosts  map[string]bool // all hosts that have events of this type
}

// handleAlerts lists recent alerts/responses/incidents.
//
//	GET /alerts?host=&type=alert&limit=
func (c *Controller) handleAlerts(w http.ResponseWriter, r *http.Request) {
	if !isLoopback(r.RemoteAddr) {
		http.Error(w, "localhost only", http.StatusForbidden)
		return
	}
	q := r.URL.Query()
	host := q.Get("host")
	typ := q.Get("type")
	if typ == "" {
		typ = "alert"
	}
	limit := 100
	if s := q.Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			limit = n
		}
	}
	out := []AlertView{}
	hosts := []string{host}
	if host == "" {
		// controller-side alerts (check red, D16, D17) live under the
		// virtual "controller" host
		hosts = append(hosts, "controller")
		hs, err := c.st.ListHosts()
		if err == nil {
			for _, h := range hs {
				hosts = append(hosts, h.Name)
			}
		}
	}
	for _, h := range hosts {
		evs, err := c.st.QueryEvents(h, typ, limit)
		if err != nil {
			continue
		}
		for _, ev := range evs {
			data := map[string]any{}
			_ = json.Unmarshal(ev.Data, &data)
			out = append(out, AlertView{Seq: ev.Seq, TS: ev.TS, Host: h, Type: typ, Data: data})
		}
	}
	json.NewEncoder(w).Encode(out)
}


// RespondRequest is the one-click tier-1 body: run one action against the
// alerting host, with the evidence on screen (docs: Response tiers).
type RespondRequest struct {
	Host   string         `json:"host"`
	Action string         `json:"action"`
	Params map[string]any `json:"params"`
	Name   string         `json:"name,omitempty"` // proposal label
}

// handleRespond is the tier-1 one-click: it builds a single-node plan
// from the action + params and runs it through the normal plan path
// (dry-run diff, approval, dead-man, rollback all apply).
func (c *Controller) handleRespond(w http.ResponseWriter, r *http.Request) {
	if !isLoopback(r.RemoteAddr) {
		http.Error(w, "localhost only", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req RespondRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Host == "" || req.Action == "" {
		http.Error(w, "host and action required", http.StatusBadRequest)
		return
	}
	name := req.Name
	if name == "" {
		name = "respond:" + req.Action
	}
	p := &plan.Plan{
		Name:  name,
		Nodes: []plan.Node{{
			ID:     "r1",
			Action: req.Action,
			Params: req.Params,
		}},
	}
	if _, err := c.RunPlan(req.Host, p, false); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]any{"plan": name, "host": req.Host, "action": req.Action})
}
