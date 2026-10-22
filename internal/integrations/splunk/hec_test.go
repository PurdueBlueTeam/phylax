package splunk

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type recorder struct {
	mu      sync.Mutex
	bodies  []string
	failFor atomic.Int32 // fail this many requests with status
	status  atomic.Int32
	block   chan struct{}
}

func (r *recorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if r.block != nil {
		<-r.block
	}
	if req.Header.Get("Authorization") != "Splunk tok" {
		w.WriteHeader(403)
		return
	}
	if r.failFor.Add(-1) >= 0 {
		w.WriteHeader(int(r.status.Load()))
		return
	}
	b, _ := io.ReadAll(req.Body)
	r.mu.Lock()
	r.bodies = append(r.bodies, string(b))
	r.mu.Unlock()
	w.Write([]byte(`{"text":"Success","code":0}`))
}

func (r *recorder) events() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, b := range r.bodies {
		n += strings.Count(b, `"event":`)
	}
	return n
}

func newFwd(t *testing.T, r *recorder, mod func(*Config)) *Forwarder {
	srv := httptest.NewTLSServer(r)
	t.Cleanup(srv.Close)
	cfg := Config{URL: srv.URL, Token: "tok", HTTPClient: srv.Client(), FlushEvery: 20 * time.Millisecond,
		Sleep: func(context.Context, time.Duration) {}}
	if mod != nil {
		mod(&cfg)
	}
	f, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func closeF(t *testing.T, f *Forwarder) {
	ctx, c := context.WithTimeout(context.Background(), 5*time.Second)
	defer c()
	if err := f.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestBatching(t *testing.T) {
	r := &recorder{}
	f := newFwd(t, r, func(c *Config) { c.MaxBatch = 10; c.FlushEvery = time.Hour })
	for i := 0; i < 25; i++ {
		f.Send(time.Now(), map[string]any{"i": i, "kind": "alert"})
	}
	closeF(t, f)
	if r.events() != 25 || len(r.bodies) != 3 {
		t.Fatalf("events=%d posts=%d", r.events(), len(r.bodies))
	}
	if !strings.Contains(r.bodies[0], `"index":"phylax"`) || f.Stats().Sent != 25 {
		t.Fatalf("%s %+v", r.bodies[0], f.Stats())
	}
}

func TestBatchBytesCap(t *testing.T) {
	r := &recorder{}
	f := newFwd(t, r, func(c *Config) { c.MaxBatchBytes = 400; c.FlushEvery = time.Hour })
	for i := 0; i < 6; i++ {
		f.Send(time.Now(), map[string]any{"pad": strings.Repeat("x", 150)})
	}
	closeF(t, f)
	for _, b := range r.bodies {
		if len(b) > 400+200 { // one event may exceed alone, never two
			t.Fatalf("batch of %d bytes", len(b))
		}
	}
	if r.events() != 6 {
		t.Fatal(r.events())
	}
}

func TestRetryThenSuccess(t *testing.T) {
	r := &recorder{}
	r.status.Store(503)
	r.failFor.Store(2)
	f := newFwd(t, r, nil)
	f.Send(time.Now(), map[string]any{"a": 1})
	closeF(t, f)
	s := f.Stats()
	if s.Sent != 1 || s.Retries != 2 || s.Failed != 0 {
		t.Fatalf("%+v", s)
	}
}

func TestRetriesExhaustedAndPermanent(t *testing.T) {
	r := &recorder{}
	r.status.Store(500)
	r.failFor.Store(1000)
	f := newFwd(t, r, func(c *Config) { c.MaxRetries = 2 })
	f.Send(time.Now(), map[string]any{"a": 1})
	closeF(t, f)
	if s := f.Stats(); s.Failed != 1 || s.Retries != 2 || f.LastError() == "" {
		t.Fatalf("%+v", s)
	}
	// 403 (wrong token) is not retried.
	r2 := &recorder{}
	f2 := newFwd(t, r2, func(c *Config) { c.Token = "wrong" })
	f2.Send(time.Now(), map[string]any{"a": 1})
	closeF(t, f2)
	if s := f2.Stats(); s.Failed != 1 || s.Retries != 0 {
		t.Fatalf("%+v", s)
	}
}

func TestBackpressureNeverBlocks(t *testing.T) {
	r := &recorder{block: make(chan struct{})}
	f := newFwd(t, r, func(c *Config) { c.QueueSize = 5; c.MaxBatch = 1; c.Timeout = 10 * time.Second })
	done := make(chan struct{})
	go func() {
		for i := 0; i < 200; i++ {
			f.Send(time.Now(), map[string]any{"i": i})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Send blocked on a stalled Splunk")
	}
	if f.Stats().Dropped < 150 {
		t.Fatalf("dropped=%d", f.Stats().Dropped)
	}
	close(r.block)
	closeF(t, f)
	if f.Send(time.Now(), nil) {
		t.Fatal("Send after Close accepted")
	}
}

func TestCloseBounded(t *testing.T) {
	r := &recorder{block: make(chan struct{})}
	f := newFwd(t, r, func(c *Config) { c.MaxBatch = 1; c.Timeout = 5 * time.Second })
	f.Send(time.Now(), map[string]any{"a": 1})
	time.Sleep(50 * time.Millisecond)
	ctx, c := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer c()
	if err := f.Close(ctx); err == nil {
		t.Fatal("Close should honour its deadline")
	}
	close(r.block)
}

func TestTLSVerifyDefault(t *testing.T) {
	srv := httptest.NewTLSServer(&recorder{})
	defer srv.Close()
	f, _ := New(Config{URL: srv.URL, Token: "tok", Timeout: time.Second, MaxRetries: 1,
		Sleep: func(context.Context, time.Duration) {}})
	f.Send(time.Now(), map[string]any{"a": 1})
	closeF(t, f)
	if f.Stats().Sent != 0 || f.Stats().Failed != 1 {
		t.Fatalf("self-signed accepted with verify on: %+v", f.Stats())
	}
	f, _ = New(Config{URL: srv.URL, Token: "tok", InsecureTLS: true})
	f.Send(time.Now(), map[string]any{"a": 1})
	closeF(t, f)
	if f.Stats().Sent != 1 {
		t.Fatalf("%+v", f.Stats())
	}
}
