//go:build windows

package winevt

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// wevtapi.dll bindings through a lazy DLL (no cgo, no generated stubs).

var (
	modWevtapi = windows.NewLazySystemDLL("wevtapi.dll")

	procEvtSubscribe      = modWevtapi.NewProc("EvtSubscribe")
	procEvtNext           = modWevtapi.NewProc("EvtNext")
	procEvtRender         = modWevtapi.NewProc("EvtRender")
	procEvtClose          = modWevtapi.NewProc("EvtClose")
	procEvtCreateBookmark = modWevtapi.NewProc("EvtCreateBookmark")
	procEvtUpdateBookmark = modWevtapi.NewProc("EvtUpdateBookmark")
)

// evtHandle is an EVT_HANDLE.
type evtHandle uintptr

// EvtSubscribe flags (winevt.h).
const (
	evtSubscribeToFutureEvents      = 1
	evtSubscribeStartAtOldestRecord = 2
	evtSubscribeStartAfterBookmark  = 3
	evtSubscribeStrict              = 0x10000
)

// EvtRender flags.
const (
	evtRenderEventXml = 1
	evtRenderBookmark = 2
)

// Error codes not in x/sys/windows.
const (
	errEvtChannelNotFound   windows.Errno = 15007
	errEvtQueryResultStale  windows.Errno = 15011
	errEvtInvalidQuery      windows.Errno = 15001
	errEvtQueryResultInvPos windows.Errno = 15012
	errInvalidParameter     windows.Errno = windows.ERROR_INVALID_PARAMETER
	errInvalidOperation     windows.Errno = 4317 // EvtNext on a future-events subscription with nothing queued yet
)

func (h evtHandle) close() {
	if h != 0 {
		procEvtClose.Call(uintptr(h))
	}
}

func evtSubscribe(signal windows.Handle, channel, query string, bookmark evtHandle, flags uint32) (evtHandle, error) {
	cp, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		return 0, err
	}
	var qp *uint16
	if query != "" {
		if qp, err = windows.UTF16PtrFromString(query); err != nil {
			return 0, err
		}
	}
	r, _, e := procEvtSubscribe.Call(0, uintptr(signal), uintptr(unsafe.Pointer(cp)), uintptr(unsafe.Pointer(qp)),
		uintptr(bookmark), 0, 0, uintptr(flags))
	if r == 0 {
		return 0, e
	}
	return evtHandle(r), nil
}

// evtNext fetches up to len(out) events without blocking. It returns
// windows.ERROR_NO_MORE_ITEMS when the queue is empty.
func evtNext(sub evtHandle, out []evtHandle) (int, error) {
	var returned uint32
	r, _, e := procEvtNext.Call(uintptr(sub), uintptr(len(out)), uintptr(unsafe.Pointer(&out[0])),
		0, 0, uintptr(unsafe.Pointer(&returned)))
	if r == 0 {
		return 0, e
	}
	return int(returned), nil
}

// evtRender renders h (event or bookmark) into UTF-8 text.
func evtRender(h evtHandle, flags uint32, buf *[]uint16) (string, error) {
	if len(*buf) == 0 {
		*buf = make([]uint16, 8192)
	}
	for {
		var used, props uint32
		size := uint32(len(*buf) * 2)
		r, _, e := procEvtRender.Call(0, uintptr(h), uintptr(flags), uintptr(size),
			uintptr(unsafe.Pointer(&(*buf)[0])), uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)))
		if r != 0 {
			n := int(used / 2)
			if n > len(*buf) {
				n = len(*buf)
			}
			// used includes the terminating NUL.
			for n > 0 && (*buf)[n-1] == 0 {
				n--
			}
			return windows.UTF16ToString((*buf)[:n]), nil
		}
		if e == windows.ERROR_INSUFFICIENT_BUFFER {
			if used > MaxXMLSize*2 {
				return "", fmt.Errorf("winevt: rendered event too large (%d bytes)", used)
			}
			*buf = make([]uint16, used/2+1)
			continue
		}
		return "", e
	}
}

func evtCreateBookmark(xml string) (evtHandle, error) {
	var p *uint16
	if xml != "" {
		var err error
		if p, err = windows.UTF16PtrFromString(xml); err != nil {
			return 0, err
		}
	}
	r, _, e := procEvtCreateBookmark.Call(uintptr(unsafe.Pointer(p)))
	if r == 0 {
		return 0, e
	}
	return evtHandle(r), nil
}

func evtUpdateBookmark(bm, ev evtHandle) error {
	r, _, e := procEvtUpdateBookmark.Call(uintptr(bm), uintptr(ev))
	if r == 0 {
		return e
	}
	return nil
}
