package winevt

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// MaxXMLSize bounds one rendered event; larger input is rejected.
const MaxXMLSize = 1 << 20

// maxValue bounds one parsed field value (bytes). Script blocks and task
// content are allowed more (maxLongValue).
const (
	maxValue     = 4096
	maxLongValue = 16384
)

// Record is one parsed Windows event.
type Record struct {
	Channel  string
	Provider string
	EventID  int
	Version  int
	Level    int
	Computer string
	Time     time.Time
	RecordID uint64
	UserSID  string
	PID      int
	// Data holds EventData and UserData items keyed by snake_case name.
	// Unnamed items are data_1, data_2, ... (1-based, in document order).
	Data map[string]string
	// Truncated lists keys whose values were cut at the size bound.
	Truncated []string
}

// ErrMalformed wraps every parse failure.
var ErrMalformed = errors.New("winevt: malformed event xml")

type xmlData struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

type xmlItem struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}

type xmlEvent struct {
	XMLName xml.Name `xml:"Event"`
	System  struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID struct {
			Value string `xml:",chardata"`
		} `xml:"EventID"`
		Version     string `xml:"Version"`
		Level       string `xml:"Level"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		EventRecordID string `xml:"EventRecordID"`
		Execution     struct {
			ProcessID string `xml:"ProcessID,attr"`
		} `xml:"Execution"`
		Channel  string `xml:"Channel"`
		Computer string `xml:"Computer"`
		Security struct {
			UserID string `xml:"UserID,attr"`
		} `xml:"Security"`
	} `xml:"System"`
	EventData struct {
		Data []xmlData `xml:"Data"`
	} `xml:"EventData"`
	UserData struct {
		Wrapper struct {
			Items []xmlItem `xml:",any"`
		} `xml:",any"`
	} `xml:"UserData"`
}

// ParseXML parses one event as produced by EvtRender(EvtRenderEventXml).
func ParseXML(b []byte) (*Record, error) {
	if len(b) > MaxXMLSize {
		return nil, fmt.Errorf("%w: %d bytes exceeds %d", ErrMalformed, len(b), MaxXMLSize)
	}
	b = bytes.TrimSpace(bytes.TrimRight(b, "\x00"))
	var x xmlEvent
	dec := xml.NewDecoder(bytes.NewReader(b))
	dec.Strict = true
	if err := dec.Decode(&x); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	id, err := strconv.Atoi(strings.TrimSpace(x.System.EventID.Value))
	if err != nil || id < 0 {
		return nil, fmt.Errorf("%w: bad EventID %q", ErrMalformed, x.System.EventID.Value)
	}
	r := &Record{
		Channel:  strings.TrimSpace(x.System.Channel),
		Provider: x.System.Provider.Name,
		EventID:  id,
		Computer: strings.TrimSpace(x.System.Computer),
		UserSID:  x.System.Security.UserID,
		Data:     map[string]string{},
	}
	r.Version, _ = strconv.Atoi(strings.TrimSpace(x.System.Version))
	r.Level, _ = strconv.Atoi(strings.TrimSpace(x.System.Level))
	r.RecordID, _ = strconv.ParseUint(strings.TrimSpace(x.System.EventRecordID), 10, 64)
	r.PID, _ = strconv.Atoi(x.System.Execution.ProcessID)
	if t, err := time.Parse(time.RFC3339Nano, x.System.TimeCreated.SystemTime); err == nil {
		r.Time = t.UTC()
	}
	put := func(k, v string) {
		limit := maxValue
		if k == "script_block_text" || k == "task_content" {
			limit = maxLongValue
		}
		if len(v) > limit {
			v = truncUTF8(v, limit)
			r.Truncated = append(r.Truncated, k)
		}
		if _, dup := r.Data[k]; dup {
			return
		}
		r.Data[k] = v
	}
	for i, d := range x.EventData.Data {
		k := d.Name
		if k == "" {
			k = "data_" + strconv.Itoa(i+1)
		} else {
			k = SnakeCase(k)
		}
		put(k, d.Value)
	}
	for _, it := range x.UserData.Wrapper.Items {
		put(SnakeCase(it.XMLName.Local), strings.TrimSpace(it.Value))
	}
	return r, nil
}

func truncUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && n < len(s) && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}

// SnakeCase converts a Windows EventData key to snake_case, keeping acronyms
// together: TargetUserName -> target_user_name, IpAddress -> ip_address,
// AttributeLDAPDisplayName -> attribute_ldap_display_name, ObjectDN -> object_dn.
func SnakeCase(s string) string {
	rs := []rune(s)
	var b strings.Builder
	for i, r := range rs {
		if unicode.IsUpper(r) && i > 0 {
			prev := rs[i-1]
			nextLower := i+1 < len(rs) && unicode.IsLower(rs[i+1])
			if unicode.IsLower(prev) || unicode.IsDigit(prev) || (unicode.IsUpper(prev) && nextLower) {
				b.WriteByte('_')
			}
		}
		switch {
		case r == ' ' || r == '-' || r == '.':
			b.WriteByte('_')
		default:
			b.WriteRune(unicode.ToLower(r))
		}
	}
	return b.String()
}

// quickRecordID extracts EventRecordID without a full parse (used for gap
// accounting of events dropped before parsing).
func quickRecordID(xmlb []byte) uint64 {
	const open = "<EventRecordID>"
	i := bytes.Index(xmlb, []byte(open))
	if i < 0 {
		return 0
	}
	rest := xmlb[i+len(open):]
	j := bytes.IndexByte(rest, '<')
	if j < 0 {
		return 0
	}
	v, _ := strconv.ParseUint(string(rest[:j]), 10, 64)
	return v
}
