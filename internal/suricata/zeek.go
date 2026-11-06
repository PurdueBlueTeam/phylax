package suricata

import (
	"encoding/json"
	"errors"
	"io"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// ReadZeek reads a Zeek conn.log or dns.log in either JSON-lines or default TSV
// form. record selects the record type (TypeZeekConn or TypeZeekDNS); the log
// type is taken from the file, so pass the matching reader for each file.
// Community IDs absent from the log are computed from the 5-tuple. The agent
// is left empty: the Host that emits these stores them under "controller".
func ReadZeek(r io.Reader, record string) ([]event.Event, ReadStats, error) {
	var st ReadStats
	var out []event.Event
	var newErr error
	switch record {
	case TypeZeekConn, TypeZeekDNS:
	default:
		return nil, st, errors.New("suricata: unknown Zeek record " + record)
	}
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
		uid, _ := m["uid"].(string)
		sec := math.Floor(ts)
		t := time.Unix(int64(sec), int64((ts-sec)*1e9)).UTC()
		var e event.Event
		if record == TypeZeekDNS {
			e, newErr = event.New(Kind, Event{Type: TypeZeekDNS,
				SrcIP: src, SrcPort: int(sp), DestIP: dst, DestPort: int(dp),
				Proto: proto, CommunityID: cid, UID: uid,
				Query: present(m, "query"), QTypeName: present(m, "qtype_name"),
				RCodeName: present(m, "rcode_name"), Answers: present(m, "answers")})
		} else {
			e, newErr = event.New(Kind, Event{Type: TypeZeekConn,
				SrcIP: src, SrcPort: int(sp), DestIP: dst, DestPort: int(dp),
				Proto: proto, CommunityID: cid, UID: uid,
				Service: present(m, "service"), ConnState: present(m, "conn_state"),
				Duration: present(m, "duration"), OrigBytes: present(m, "orig_bytes"),
				RespBytes: present(m, "resp_bytes")})
		}
		if newErr != nil {
			return
		}
		e.Priority = event.PriorityBulk
		e.Time = t
		out = append(out, e)
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
	if newErr != nil {
		return nil, st, newErr
	}
	return out, st, err
}

// present returns a log field unless the log left it empty (Zeek writes "-"
// for a field it did not fill, and JSON-lines logs omit it).
func present(m map[string]any, key string) any {
	if v, ok := m[key]; ok && v != "-" && v != nil {
		return v
	}
	return nil
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
