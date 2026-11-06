package controller

import "time"

// clock is the timer source of the analysis worker. Tests inject a fake so
// debounce and max-wait behaviour is deterministic.
type clock interface {
	Now() time.Time
	NewTimer(d time.Duration) timer
	NewTicker(d time.Duration) ticker
}

type timer interface {
	C() <-chan time.Time
	Stop()
	Reset(d time.Duration)
}

type ticker interface {
	C() <-chan time.Time
	Stop()
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

func (realClock) NewTimer(d time.Duration) timer { return &realTimer{t: time.NewTimer(d)} }

func (realClock) NewTicker(d time.Duration) ticker { return &realTicker{t: time.NewTicker(d)} }

type realTimer struct{ t *time.Timer }

func (t *realTimer) C() <-chan time.Time { return t.t.C }

func (t *realTimer) Stop() { t.t.Stop() }

func (t *realTimer) Reset(d time.Duration) { t.t.Reset(d) }

type realTicker struct{ t *time.Ticker }

func (t *realTicker) C() <-chan time.Time { return t.t.C }

func (t *realTicker) Stop() { t.t.Stop() }
