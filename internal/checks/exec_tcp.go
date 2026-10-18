package checks

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	tcpBannerReadLimit = 1 << 10 // read up to 1 KiB
	tcpBannerReadTime  = 2 * time.Second
	tcpBannerMaxLen    = 200
)

// runTCP connects, reads the banner (up to 1 KiB for up to 2s) and reports
// it. The banner is truncated at a NUL or the first non-printable byte and
// capped at 200 bytes; the check's expected banner_re is matched against it
// (unanchored).
func runTCP(ctx context.Context, ck Check) (map[string]any, error) {
	host, err := pstr(ck.Params, "host")
	if err != nil {
		return nil, err
	}
	addr, err := addrWithDefaultPort(host, ck)
	if err != nil {
		return nil, fmt.Errorf("tcp: %v", err)
	}
	conn, err := dialContext(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("tcp: %v", err)
	}
	defer conn.Close()

	readTime := tcpBannerReadTime
	if dl, ok := ctx.Deadline(); ok {
		if d := time.Until(dl); d < readTime {
			readTime = d
		}
	}
	if err := conn.SetReadDeadline(time.Now().Add(readTime)); err != nil {
		return nil, fmt.Errorf("tcp: %v", err)
	}
	raw, err := io.ReadAll(io.LimitReader(conn, tcpBannerReadLimit))
	if err != nil && len(raw) == 0 {
		return nil, fmt.Errorf("tcp: read: %v", err)
	}
	// A banner that stops at EOF or the read limit is fine; a mid-read
	// error after some bytes is not.
	return map[string]any{"banner": printableBanner(raw)}, nil
}

// printableBanner trims the raw banner to printable form: first 200 bytes,
// stopping at a NUL or the first non-printable byte.
func printableBanner(raw []byte) string {
	var b []byte
	for _, c := range raw {
		if c == 0 {
			break
		}
		if c < 0x20 && c != '\t' && c != '\n' && c != '\r' {
			break
		}
		if c >= 0x7f {
			break
		}
		b = append(b, c)
		if len(b) == tcpBannerMaxLen {
			break
		}
	}
	return string(b)
}

// dialContext dials TCP following the context deadline.
func dialContext(ctx context.Context, addr string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
}
