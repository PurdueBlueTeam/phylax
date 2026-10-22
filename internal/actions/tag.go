package actions

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Tag identifies our own changes (design: Tagging and adoption). It travels in
// the context so every event emitted while an action runs can carry it.
type Tag struct {
	Plan   string `json:"plan,omitempty"`
	Node   string `json:"node,omitempty"`
	Window string `json:"window,omitempty"` // patch window
}

func (t Tag) IsZero() bool { return t == Tag{} }

// String is the compact form embedded in resource comments (keys, GECOS).
func (t Tag) String() string {
	if t.Plan == "" {
		return "phylax"
	}
	return "phylax:" + t.Plan
}

type tagKey struct{}

func WithTag(ctx context.Context, t Tag) context.Context { return context.WithValue(ctx, tagKey{}, t) }
func TagFrom(ctx context.Context) Tag                    { t, _ := ctx.Value(tagKey{}).(Tag); return t }

// TagRecord says that Action, under Tag, changed Resource.
type TagRecord struct {
	Time     time.Time `json:"time"`
	Tag      Tag       `json:"tag"`
	Action   string    `json:"action"`
	Resource string    `json:"resource"`
}

// TagSink records tagged changes so detection can recognise them.
type TagSink interface{ Record(TagRecord) error }

// TagLog is a JSON-lines file plus an in-memory index of the latest record per
// resource. The file is bounded; at the bound new records stop being appended
// to disk but remain in the index.
type TagLog struct {
	mu    sync.Mutex
	path  string
	size  int64
	max   int64
	index map[string]TagRecord
}

const tagLogMax = 8 << 20

func OpenTagLog(path string) (*TagLog, error) {
	l := &TagLog{path: path, max: tagLogMax, index: map[string]TagRecord{}}
	f, err := os.Open(path)
	if err == nil {
		defer f.Close()
		st, _ := f.Stat()
		if st != nil {
			l.size = st.Size()
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			var r TagRecord
			if json.Unmarshal(sc.Bytes(), &r) == nil {
				l.index[r.Resource] = r
			}
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return l, nil
}

func (l *TagLog) Record(r TagRecord) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.index[r.Resource] = r
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if l.size+int64(len(b)) > l.max {
		return nil
	}
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	n, err := f.Write(b)
	l.size += int64(n)
	return err
}

// Lookup returns the latest tagged change to resource.
func (l *TagLog) Lookup(resource string) (TagRecord, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	r, ok := l.index[resource]
	return r, ok
}
