// Package splunk forwards Phylax alerts to a Splunk HTTP Event Collector as
// evidence the judges can see. It is strictly best-effort: Send never blocks,
// the queue is bounded (overflow drops and counts), and a dead Splunk only
// increments counters.
package splunk

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"time"
)

// Config configures the forwarder.
type Config struct {
	URL         string // https://splunk:8088
	Token       string
	Index       string // default "phylax"
	Source      string // default "phylax"
	SourceType  string // default "_json"
	Host        string
	CAPEM       []byte
	InsecureTLS bool // verify is ON unless set

	QueueSize     int           // default 1024 events
	MaxBatch      int           // events per POST, default 100
	MaxBatchBytes int           // default 512 KiB
	FlushEvery    time.Duration // default 2s
	MaxRetries    int           // per batch, default 4
	BackoffBase   time.Duration // default 500ms, doubled per retry, capped 30s
	Timeout       time.Duration // per request, default 5s

	HTTPClient *http.Client
	Sleep      func(context.Context, time.Duration) // tests
}

// Stats are cumulative counters.
type Stats struct {
	Sent, Dropped, Retries, Failed uint64
}

// Forwarder is a bounded, non-blocking HEC client.
type Forwarder struct {
	cfg  Config
	hc   *http.Client
	q    chan hecEvent
	wg   sync.WaitGroup
	once sync.Once
	stop chan struct{}

	sent, dropped, retries, failed atomic.Uint64
	lastErr                        atomic.Value // string
}

type hecEvent struct {
	Time       float64        `json:"time"`
	Host       string         `json:"host,omitempty"`
	Source     string         `json:"source,omitempty"`
	SourceType string         `json:"sourcetype,omitempty"`
	Index      string         `json:"index,omitempty"`
	Event      map[string]any `json:"event"`
}

// New starts the forwarder goroutine.
func New(cfg Config) (*Forwarder, error) {
	if cfg.URL == "" || cfg.Token == "" {
		return nil, errors.New("splunk: URL and Token required")
	}
	def := func(p *int, v int) {
		if *p <= 0 {
			*p = v
		}
	}
	def(&cfg.QueueSize, 1024)
	def(&cfg.MaxBatch, 100)
	def(&cfg.MaxBatchBytes, 512<<10)
	def(&cfg.MaxRetries, 4)
	if cfg.FlushEvery <= 0 {
		cfg.FlushEvery = 2 * time.Second
	}
	if cfg.BackoffBase <= 0 {
		cfg.BackoffBase = 500 * time.Millisecond
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.Index == "" {
		cfg.Index = "phylax"
	}
	if cfg.Source == "" {
		cfg.Source = "phylax"
	}
	if cfg.SourceType == "" {
		cfg.SourceType = "_json"
	}
	if cfg.Sleep == nil {
		cfg.Sleep = func(ctx context.Context, d time.Duration) {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-t.C:
			case <-ctx.Done():
			}
		}
	}
	hc := cfg.HTTPClient
	if hc == nil {
		tc := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.InsecureTLS}
		if len(cfg.CAPEM) > 0 {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(cfg.CAPEM) {
				return nil, errors.New("splunk: bad CA PEM")
			}
			tc.RootCAs = pool
		}
		hc = &http.Client{Timeout: cfg.Timeout, Transport: &http.Transport{TLSClientConfig: tc, MaxIdleConns: 2}}
	}
	f := &Forwarder{cfg: cfg, hc: hc, q: make(chan hecEvent, cfg.QueueSize), stop: make(chan struct{})}
	f.wg.Add(1)
	go f.run()
	return f, nil
}

// Send queues an event. It never blocks; false means it was dropped (queue
// full or forwarder closed).
func (f *Forwarder) Send(t time.Time, fields map[string]any) bool {
	select {
	case <-f.stop:
		f.dropped.Add(1)
		return false
	default:
	}
	e := hecEvent{Time: float64(t.UnixNano()) / 1e9, Host: f.cfg.Host, Source: f.cfg.Source,
		SourceType: f.cfg.SourceType, Index: f.cfg.Index, Event: fields}
	select {
	case f.q <- e:
		return true
	default:
		f.dropped.Add(1)
		return false
	}
}

// Stats returns the counters.
func (f *Forwarder) Stats() Stats {
	return Stats{f.sent.Load(), f.dropped.Load(), f.retries.Load(), f.failed.Load()}
}

// LastError is the most recent delivery error, "" if none.
func (f *Forwarder) LastError() string { s, _ := f.lastErr.Load().(string); return s }

// Close stops accepting events and flushes what is queued, bounded by ctx.
func (f *Forwarder) Close(ctx context.Context) error {
	f.once.Do(func() { close(f.stop) })
	done := make(chan struct{})
	go func() { f.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (f *Forwarder) run() {
	defer f.wg.Done()
	// A deadline context for the final drain is set by Close via stop; the
	// delivery context itself is cancelled only when retries are exhausted.
	tick := time.NewTicker(f.cfg.FlushEvery)
	defer tick.Stop()
	var buf bytes.Buffer
	n := 0
	flush := func() {
		if n > 0 {
			f.deliver(buf.Bytes(), n)
			buf.Reset()
			n = 0
		}
	}
	add := func(e hecEvent) {
		b, err := json.Marshal(e)
		if err != nil {
			f.dropped.Add(1)
			return
		}
		if n > 0 && buf.Len()+len(b) > f.cfg.MaxBatchBytes {
			flush()
		}
		buf.Write(b)
		n++
		if n >= f.cfg.MaxBatch {
			flush()
		}
	}
	for {
		select {
		case e := <-f.q:
			add(e)
		case <-tick.C:
			flush()
		case <-f.stop:
			for {
				select {
				case e := <-f.q:
					add(e)
				default:
					flush()
					return
				}
			}
		}
	}
}

// permanent errors are not retried (bad token, bad index, malformed).
type permanent struct{ error }

func (f *Forwarder) deliver(body []byte, n int) {
	body = append([]byte(nil), body...)
	ctx := context.Background()
	backoff := f.cfg.BackoffBase
	var err error
	for attempt := 0; attempt <= f.cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			f.retries.Add(1)
			f.cfg.Sleep(ctx, backoff)
			if backoff *= 2; backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
		}
		if err = f.post(ctx, body); err == nil {
			f.sent.Add(uint64(n))
			f.lastErr.Store("")
			return
		}
		var p permanent
		if errors.As(err, &p) {
			break
		}
	}
	f.failed.Add(uint64(n))
	f.lastErr.Store(err.Error())
}

func (f *Forwarder) post(ctx context.Context, body []byte) error {
	ctx, cancel := context.WithTimeout(ctx, f.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(f.cfg.URL, "/")+"/services/collector/event", bytes.NewReader(body))
	if err != nil {
		return permanent{err}
	}
	req.Header.Set("Authorization", "Splunk "+f.cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	switch {
	case resp.StatusCode == 200:
		return nil
	case resp.StatusCode == 429 || resp.StatusCode >= 500:
		return fmt.Errorf("splunk: HEC HTTP %d", resp.StatusCode)
	default: // 400 bad data, 401/403 bad token, 404 wrong path
		return permanent{fmt.Errorf("splunk: HEC HTTP %d", resp.StatusCode)}
	}
}

// SendEvent forwards a Phylax event (kind, agent, fields) as a HEC event.
func (f *Forwarder) SendEvent(e event.Event) bool {
	m := map[string]any{"phylax_kind": e.Kind, "phylax_agent": e.Agent, "phylax_seq": e.Seq, "phylax_hash": e.Hash}
	for k, v := range e.Fields {
		m[k] = v
	}
	return f.Send(e.Time, m)
}
