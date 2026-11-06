// Package suricata reads Suricata EVE JSON and Zeek logs from disk (offline,
// from frozen pcap slices) and turns them into Phylax events joined by
// Community ID. Nothing here runs live.
package suricata

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

const (
	maxLine = 1 << 20 // longer lines are skipped and counted
)

// ReadStats counts what the readers skipped.
type ReadStats struct {
	Lines, Bad, TooLong, Skipped int
}

type eveRecord struct {
	Timestamp   string `json:"timestamp"`
	FlowID      int64  `json:"flow_id"`
	EventType   string `json:"event_type"`
	SrcIP       string `json:"src_ip"`
	SrcPort     int    `json:"src_port"`
	DestIP      string `json:"dest_ip"`
	DestPort    int    `json:"dest_port"`
	Proto       string `json:"proto"`
	CommunityID string `json:"community_id"`
	Interface   string `json:"in_iface"`
	Alert       *struct {
		Action      string `json:"action"`
		GID         int    `json:"gid"`
		SignatureID int    `json:"signature_id"`
		Rev         int    `json:"rev"`
		Signature   string `json:"signature"`
		Category    string `json:"category"`
		Severity    int    `json:"severity"`
	} `json:"alert"`
	DNS *struct {
		RRName string `json:"rrname"`
		RRType string `json:"rrtype"`
	} `json:"dns"`
	HTTP *struct {
		Hostname string `json:"hostname"`
		URL      string `json:"url"`
		Method   string `json:"http_method"`
	} `json:"http"`
}

// ParseTime parses Suricata's "2026-10-22T10:00:00.123456+0000" timestamps.
func parseEveTime(s string) (time.Time, error) {
	for _, l := range []string{"2006-01-02T15:04:05.999999-0700", time.RFC3339Nano} {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, errors.New("suricata: bad timestamp " + s)
}

func lines(r io.Reader, st *ReadStats, fn func([]byte)) error {
	br := bufio.NewReaderSize(r, maxLine)
	for {
		line, err := br.ReadSlice('\n')
		switch {
		case err == bufio.ErrBufferFull: // discard the rest of an oversize line
			st.TooLong++
			for err == bufio.ErrBufferFull {
				_, err = br.ReadSlice('\n')
			}
			st.Lines++
			if err != nil {
				return nilEOF(err)
			}
			continue
		case err != nil && len(line) == 0:
			return nilEOF(err)
		}
		st.Lines++
		if l := strings.TrimSpace(string(line)); l != "" {
			fn([]byte(l))
		}
		if err != nil {
			return nilEOF(err)
		}
	}
}

func nilEOF(err error) error {
	if err == io.EOF {
		return nil
	}
	return err
}

// ReadEVE reads EVE JSON and returns an event per alert (and, if includeDNS,
// per dns/http record as context). Events are sorted by time. A malformed line
// is skipped and counted, never fatal. The agent is left empty: the Host that
// emits these stores them under "controller".
func ReadEVE(r io.Reader, includeContext bool) ([]event.Event, ReadStats, error) {
	var st ReadStats
	var out []event.Event
	var newErr error
	err := lines(r, &st, func(b []byte) {
		var rec eveRecord
		if json.Unmarshal(b, &rec) != nil {
			st.Bad++
			return
		}
		t, terr := parseEveTime(rec.Timestamp)
		if terr != nil {
			st.Bad++
			return
		}
		cid := rec.CommunityID
		if cid == "" {
			cid = CommunityID(rec.SrcIP, rec.DestIP, uint16(rec.SrcPort), uint16(rec.DestPort), rec.Proto)
		}
		var e event.Event
		switch {
		case rec.EventType == "alert" && rec.Alert != nil:
			e, newErr = event.New(KindAlert, Alert{
				SrcIP: rec.SrcIP, SrcPort: rec.SrcPort, DestIP: rec.DestIP, DestPort: rec.DestPort,
				Proto: rec.Proto, CommunityID: cid, FlowID: rec.FlowID,
				SignatureID: rec.Alert.SignatureID, Signature: rec.Alert.Signature,
				Category: rec.Alert.Category, Severity: rec.Alert.Severity, Action: rec.Alert.Action})
			if newErr != nil {
				return
			}
			e.Priority = prio(rec.Alert.Severity) // the kind's default is normal
		case includeContext && rec.EventType == "dns" && rec.DNS != nil:
			e, newErr = event.New(KindDNS, DNS{
				SrcIP: rec.SrcIP, SrcPort: rec.SrcPort, DestIP: rec.DestIP, DestPort: rec.DestPort,
				Proto: rec.Proto, CommunityID: cid, FlowID: rec.FlowID,
				RRName: rec.DNS.RRName, RRType: rec.DNS.RRType})
		case includeContext && rec.EventType == "http" && rec.HTTP != nil:
			e, newErr = event.New(KindHTTP, HTTP{
				SrcIP: rec.SrcIP, SrcPort: rec.SrcPort, DestIP: rec.DestIP, DestPort: rec.DestPort,
				Proto: rec.Proto, CommunityID: cid, FlowID: rec.FlowID,
				Hostname: rec.HTTP.Hostname, URL: rec.HTTP.URL, Method: rec.HTTP.Method})
		default:
			st.Skipped++
			return
		}
		if newErr != nil {
			return
		}
		e.Time = t
		out = append(out, e)
	})
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.Before(out[j].Time) })
	if newErr != nil {
		return nil, st, newErr
	}
	return out, st, err
}

// prio maps Suricata severity (1 high .. 3 low) to event priority.
func prio(sev int) event.Priority {
	switch sev {
	case 1:
		return event.PriorityHigh
	case 2:
		return event.PriorityNormal
	}
	return event.PriorityBulk
}

// Join groups events by Community ID (events without one are omitted).
func Join(evs ...[]event.Event) map[string][]event.Event {
	m := map[string][]event.Event{}
	for _, l := range evs {
		for _, e := range l {
			if id, _ := e.Fields["community_id"].(string); id != "" {
				m[id] = append(m[id], e)
			}
		}
	}
	for _, l := range m {
		sort.SliceStable(l, func(i, j int) bool { return l[i].Time.Before(l[j].Time) })
	}
	return m
}
