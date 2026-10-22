package capture

import (
	"fmt"
	"net/netip"
	"strconv"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/parsers/txn"
)

// KindHTTPRequest is the detection event for one parsed HTTP exchange. Fields:
// method, host, uri (path and query), ua, status (when a response was seen),
// src_ip, src_port, dst_ip, dst_port, community_id, plus dst_org and dst_cloud
// from the configured network list (see OrgNet).
const KindHTTPRequest = "http_request"

// OrgNet labels a set of destination networks, for example the published
// Microsoft ranges or a cloud provider's. The list is configuration, never
// compiled in: ranges change and the red team picks its own hosting.
type OrgNet struct {
	Org   string   // dst_org value, e.g. "microsoft", "aws"
	Cloud bool     // sets dst_cloud (a commodity hosting/cloud range)
	CIDRs []string // prefixes
}

// HTTPEvents converts HTTP transactions to http_request events.
type HTTPEvents struct {
	nets []orgPrefixes
}

type orgPrefixes struct {
	org      string
	cloud    bool
	prefixes []netip.Prefix
}

// NewHTTPEvents validates the network list.
func NewHTTPEvents(nets []OrgNet) (*HTTPEvents, error) {
	h := &HTTPEvents{}
	for i, n := range nets {
		if n.Org == "" {
			return nil, fmt.Errorf("capture: org net %d has no org name", i)
		}
		op := orgPrefixes{org: n.Org, cloud: n.Cloud}
		for _, c := range n.CIDRs {
			p, err := netip.ParsePrefix(c)
			if err != nil {
				return nil, fmt.Errorf("capture: org net %q: bad CIDR %q", n.Org, c)
			}
			op.prefixes = append(op.prefixes, p.Masked())
		}
		h.nets = append(h.nets, op)
	}
	return h, nil
}

func (h *HTTPEvents) classify(a netip.Addr) (org string, cloud bool) {
	a = a.Unmap()
	for _, n := range h.nets {
		for _, p := range n.prefixes {
			if p.Contains(a) {
				return n.org, n.cloud
			}
		}
	}
	return "", false
}

// Event converts one transaction; ok is false for anything but an HTTP
// exchange. The event time is the request start. Credentials never appear:
// only the request line, Host and User-Agent are copied.
func (h *HTTPEvents) Event(t txn.Txn) (event.Event, bool) {
	if t.Proto != "http" || t.Type != "exchange" {
		return event.Event{}, false
	}
	f := map[string]any{
		"method": t.Attr["http.method"], "host": t.Attr["http.host"],
		"uri": t.Attr["http.path"], "ua": t.Attr["http.ua"],
		"src_ip": t.Client.Addr().String(), "src_port": int(t.Client.Port()),
		"dst_ip": t.Server.Addr().String(), "dst_port": int(t.Server.Port()),
	}
	if t.CommunityID != "" {
		f["community_id"] = t.CommunityID
	}
	if s, ok := t.Attr["http.status"]; ok {
		if n, err := strconv.Atoi(s); err == nil {
			f["status"] = n
		}
	}
	if org, cloud := h.classify(t.Server.Addr()); org != "" || cloud {
		if org != "" {
			f["dst_org"] = org
		}
		if cloud {
			f["dst_cloud"] = true
		}
	}
	return event.Event{Time: t.Time, Kind: KindHTTPRequest, Priority: event.PriorityNormal, Fields: f}, true
}
