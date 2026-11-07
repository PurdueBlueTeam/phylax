//go:build windows

package winevt

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
)

const platformSupported = true

const evtBatch = 128

// subscription is a pull-model EvtSubscribe with a signal event.
type subscription struct {
	channel string
	sub     evtHandle
	bm      evtHandle
	signal  windows.Handle
	buf     []uint16
}

// platformOpen subscribes to ch. With a bookmark it resumes strictly after it
// (a missing record yields ErrBookmarkStale); without one it starts at the
// oldest record (fromOldest) or at future events.
func platformOpen(_ context.Context, ch Channel, bookmark string, fromOldest bool) (Source, error) {
	// Manual-reset, initially signalled, as in Microsoft's pull-model sample.
	sig, err := windows.CreateEvent(nil, 1, 1, nil)
	if err != nil {
		return nil, fmt.Errorf("winevt: CreateEvent: %w", err)
	}
	s := &subscription{channel: ch.Name, signal: sig}
	bmh, err := evtCreateBookmark(bookmark)
	if err != nil {
		windows.CloseHandle(sig)
		return nil, fmt.Errorf("winevt: EvtCreateBookmark: %w", err)
	}
	s.bm = bmh
	var h evtHandle
	var flags uint32
	switch {
	case bookmark != "":
		flags = evtSubscribeStartAfterBookmark | evtSubscribeStrict
		h, err = evtSubscribe(sig, ch.Name, ch.Query(), bmh, flags)
	case fromOldest:
		h, err = evtSubscribe(sig, ch.Name, ch.Query(), 0, evtSubscribeStartAtOldestRecord)
	default:
		h, err = evtSubscribe(sig, ch.Name, ch.Query(), 0, evtSubscribeToFutureEvents)
	}
	if err != nil {
		s.Close()
		return nil, classifyOpenErr(err)
	}
	s.sub = h
	return s, nil
}

func classifyOpenErr(err error) error {
	var en windows.Errno
	if errors.As(err, &en) {
		switch en {
		case errEvtChannelNotFound, windows.ERROR_FILE_NOT_FOUND:
			return fmt.Errorf("%w: %v", ErrChannelNotFound, err)
		case errEvtQueryResultStale, errEvtInvalidQuery, errEvtQueryResultInvPos, errInvalidParameter:
			// Strict resume with a removed record, a malformed saved bookmark
			// or a rejected bookmark handle: resubscribe from the oldest record.
			return fmt.Errorf("%w: %v", ErrBookmarkStale, err)
		}
	}
	return fmt.Errorf("winevt: EvtSubscribe: %w", err)
}

func (s *subscription) Close() error {
	s.sub.close()
	s.bm.close()
	if s.signal != 0 {
		windows.CloseHandle(s.signal)
		s.signal = 0
	}
	return nil
}

// Next returns the next batch, waiting on the signal event (polling ctx every
// 500 ms).
func (s *subscription) Next(ctx context.Context) (Batch, error) {
	var handles [evtBatch]evtHandle
	for {
		if err := ctx.Err(); err != nil {
			return Batch{}, err
		}
		n, err := evtNext(s.sub, handles[:])
		switch {
		case err == nil:
			return s.drain(handles[:n])
		case errors.Is(err, windows.ERROR_NO_MORE_ITEMS), errors.Is(err, errInvalidOperation):
			windows.ResetEvent(s.signal)
			// Re-check once to close the race between EvtNext and ResetEvent.
			if n2, err2 := evtNext(s.sub, handles[:]); err2 == nil {
				return s.drain(handles[:n2])
			}
			if _, werr := windows.WaitForSingleObject(s.signal, 500); werr != nil {
				return Batch{}, fmt.Errorf("winevt: wait: %w", werr)
			}
		case errors.Is(err, errEvtQueryResultStale), errors.Is(err, errEvtQueryResultInvPos):
			return Batch{}, fmt.Errorf("%w: %v", ErrBookmarkStale, err)
		default:
			return Batch{}, fmt.Errorf("winevt: EvtNext: %w", err)
		}
	}
}

func (s *subscription) drain(hs []evtHandle) (Batch, error) {
	var b Batch
	defer func() {
		for _, h := range hs {
			h.close()
		}
	}()
	for _, h := range hs {
		x, err := evtRender(h, evtRenderEventXml, &s.buf)
		if err != nil {
			// Skip an unrenderable event but keep position moving; the pipeline
			// has no XML to count, so surface it as an error-free empty slot.
			b.Events = append(b.Events, []byte("<Event/>"))
		} else {
			b.Events = append(b.Events, []byte(x))
		}
		if err := evtUpdateBookmark(s.bm, h); err != nil {
			return b, fmt.Errorf("winevt: EvtUpdateBookmark: %w", err)
		}
	}
	bx, err := evtRender(s.bm, evtRenderBookmark, &s.buf)
	if err != nil {
		return b, fmt.Errorf("winevt: render bookmark: %w", err)
	}
	b.Bookmark = bx
	return b, nil
}
