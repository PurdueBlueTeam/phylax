// Package parsertest drives stream parsers in tests: scripted exchanges and a
// shared fuzz body that feeds arbitrary bytes split across both directions.
package parsertest

import (
	"net/netip"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/parsers/txn"
)

// Step is bytes flowing in one direction.
type Step struct {
	Dir  txn.Dir
	Data []byte
}

// C2S and S2C build steps.
func C2S(b []byte) Step { return Step{txn.C2S, b} }
func S2C(b []byte) Step { return Step{txn.S2C, b} }

// Ctor builds a parser.
type Ctor func(txn.Meta, txn.Emit) txn.Stream

// Meta is the flow every test uses.
func Meta() txn.Meta {
	return txn.Meta{
		Client: netip.MustParseAddrPort("10.0.0.5:51000"), Server: netip.MustParseAddrPort("10.0.0.9:80"),
		CommunityID: "1:test", Start: time.Unix(1700000000, 0),
	}
}

// T0 is the first timestamp; each step advances 10 ms.
var T0 = time.Unix(1700000000, 0)

// Run feeds steps, ends the stream and returns what it emitted. Steps are
// delivered whole; use SplitBytes to also test arbitrary segmentation.
func Run(c Ctor, steps ...Step) []txn.Txn { return RunMeta(c, Meta(), steps...) }

// RunMeta is Run with a custom Meta.
func RunMeta(c Ctor, m txn.Meta, steps ...Step) []txn.Txn {
	var out []txn.Txn
	s := c(m, func(t txn.Txn) { out = append(out, t) })
	ts := T0
	for _, st := range steps {
		s.Data(st.Dir, st.Data, ts)
		ts = ts.Add(10 * time.Millisecond)
	}
	s.End(ts)
	return out
}

// Resegment splits every step into pieces of n bytes (n=1 is the worst case).
func Resegment(steps []Step, n int) []Step {
	var out []Step
	for _, st := range steps {
		for b := st.Data; len(b) > 0; {
			k := min(n, len(b))
			out = append(out, Step{st.Dir, b[:k]})
			b = b[k:]
		}
	}
	return out
}

// Encode packs steps into the fuzz input format: a control byte (direction in
// bit 0, length-1 in the upper 7 bits) before each chunk of up to 128 bytes.
func Encode(steps []Step) []byte {
	var out []byte
	for _, st := range steps {
		for b := st.Data; len(b) > 0; {
			k := min(128, len(b))
			out = append(out, byte(k-1)<<1|byte(st.Dir&1))
			out = append(out, b[:k]...)
			b = b[k:]
		}
	}
	return out
}

func decode(data []byte) []Step {
	var out []Step
	for len(data) > 0 {
		c := data[0]
		n := int(c>>1) + 1
		data = data[1:]
		if n > len(data) {
			n = len(data)
		}
		out = append(out, Step{txn.Dir(c & 1), data[:n]})
		data = data[n:]
	}
	return out
}

// Fuzz registers seeds and the common body: any input must not panic, and
// every emitted transaction must carry its protocol and no nil maps issues.
func Fuzz(f *testing.F, c Ctor, seeds ...[]Step) {
	for _, s := range seeds {
		f.Add(Encode(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, tx := range RunMeta(c, Meta(), decode(data)...) {
			if tx.Proto == "" || tx.Type == "" {
				t.Fatalf("transaction without proto/type: %+v", tx)
			}
			for k, v := range tx.Attr {
				if len(v) > 4096 {
					t.Fatalf("attr %s unbounded: %d bytes", k, len(v))
				}
			}
		}
	})
}
