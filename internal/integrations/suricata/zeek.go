package suricata

import (
	"encoding/json"
	"io"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// ReadZeek reads a Zeek conn.log or dns.log in either JSON-lines or default TSV
// form. kind selects the event kind (KindZeekConn or KindZeekDNS); the log type
// is taken from the file, so pass the matching reader for each file. Community
// IDs absent from the log are computed from the 5-tuple.
func ReadZeek(r io.Reader, kind string) ([]event.Event, ReadStats, error) {
	var st ReadStats
	var out []event.Event
	var fields []string
	emit := func(m map[string]any) {
		ts, ok := num(m["ts"])
		if !ok {
			st.Bad++
			return
		}
		src, _ := m["id.orig_h"].(string)
		dst, _ := m["id.resp_h"].(string)
		sp, _ := num(m["id.orig_p"])
		dp, _ := num(m["id.resp_p"])
		proto, _ := m["proto"].(string)
		cid, _ := m["community_id"].(string)
		if cid == "" {
			cid = CommunityID(src, dst, uint16(sp), uint16(dp), proto)
		}
		f := map[string]any{"src_ip": src, "src_port": int(sp), "dest_ip": dst, "dest_port": int(dp),
			"proto": proto, "community_id": cid, "uid": m["uid"]}
		for _, k := range []string{"service", "conn_state", "duration", "orig_bytes", "resp_bytes", "query", "qtype_name", "rcode_name", "answers"} {
			if v, ok := m[k]; ok && v != "-" && v != nil {
				f[k] = v
			}
		}
		sec := math.Floor(ts)
		out = append(out, event.Event{Agent: "zeek", Kind: kind, Priority: event.PriorityBulk, Fields: f,
			Time: time.Unix(int64(sec), int64((ts-sec)*1e9)).UTC()})
	}
	err := lines(r, &st, func(b []byte) {
		if b[0] == '#' {
			if rest, ok := strings.CutPrefix(string(b), "#fields"); ok {
				fields = strings.Split(strings.TrimPrefix(rest, "\t"), "\t")
			}
			return
		}
		if b[0] == '{' {
			var m map[string]any
			if json.Unmarshal(b, &m) != nil {
				st.Bad++
				return
			}
			emit(m)
			return
		}
		if fields == nil {
			st.Bad++
			return
		}
		cols := strings.Split(string(b), "\t")
		if len(cols) != len(fields) {
			st.Bad++
			return
		}
		m := make(map[string]any, len(cols))
		for i, c := range cols {
			m[fields[i]] = c
		}
		emit(m)
	})
	return out, st, err
}

func num(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case string:
		f, err := strconv.ParseFloat(x, 64)
		return f, err == nil
	}
	return 0, false
}
