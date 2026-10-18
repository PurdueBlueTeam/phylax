package checks

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

const (
	tftpBlockSize  = 512
	tftpExchangeTO = 3 * time.Second
	tftpMaxRetries = 3
	tftpOpRRQ      = 1
	tftpOpDATA     = 3
	tftpOpACK      = 4
	tftpOpERR      = 5
)

// runTFTP fetches the file with a minimal RRQ client (legacy 512-byte
// blocks, 3s exchange timeout, 3 retries) and reports its sha256.
func runTFTP(ctx context.Context, ck Check) (map[string]any, error) {
	host, err := pstr(ck.Params, "host")
	if err != nil {
		return nil, err
	}
	file, err := pstr(ck.Params, "file")
	if err != nil {
		return nil, err
	}
	addr, err := addrWithDefaultPort(host, ck)
	if err != nil {
		return nil, fmt.Errorf("tftp: %v", err)
	}
	conn, err := net.DialTimeout("udp", addr, dialTimeout(ctx))
	if err != nil {
		return nil, fmt.Errorf("tftp: %v", err)
	}
	defer conn.Close()
	if err := setConnDeadline(conn, ctx); err != nil {
		return nil, fmt.Errorf("tftp: %v", err)
	}

	req := append([]byte{0, tftpOpRRQ}, file...)
	req = append(req, 0, 'o', 'c', 't', 'e', 't', 0)
	if _, err := conn.Write(req); err != nil {
		return nil, fmt.Errorf("tftp: %v", err)
	}

	var body []byte
	block := 1
	for {
		data, err := tftpWaitData(conn, block)
		if err != nil {
			return nil, fmt.Errorf("tftp: block %d: %v", block, err)
		}
		if err := tftpSend(conn, tftpAck(block)); err != nil {
			return nil, fmt.Errorf("tftp: ack %d: %v", block, err)
		}
		body = append(body, data...)
		if len(data) < tftpBlockSize {
			break
		}
		block++
	}
	return map[string]any{"sha256": sha256Hex(body)}, nil
}

func tftpAck(block int) []byte {
	b := make([]byte, 4)
	b[0] = 0
	b[1] = tftpOpACK
	binary.BigEndian.PutUint16(b[2:4], uint16(block))
	return b
}

// tftpWaitData waits for block, retransmitting the previous ACK on
// timeout (the TFTP restart mechanism).
func tftpWaitData(conn net.Conn, block int) ([]byte, error) {
	buf := make([]byte, 4+tftpBlockSize)
	for attempt := range tftpMaxRetries + 1 {
		if attempt > 0 {
			if err := tftpSend(conn, tftpAck(block-1)); err != nil {
				return nil, err
			}
		}
		if err := conn.SetReadDeadline(time.Now().Add(tftpExchangeTO)); err != nil {
			return nil, err
		}
		n, err := conn.Read(buf)
		if err != nil {
			continue // timeout: retry
		}
		if n < 4 {
			continue
		}
		op := binary.BigEndian.Uint16(buf[0:2])
		switch op {
		case tftpOpERR:
			return nil, tftpError(n, buf)
		case tftpOpDATA:
			if seq := binary.BigEndian.Uint16(buf[2:4]); seq == uint16(block) {
				return buf[4:n], nil
			}
			// duplicate or early block: wait again
		}
	}
	return nil, fmt.Errorf("no data after %d retries", tftpMaxRetries)
}

// tftpSend writes one packet, bounding the write by the exchange timeout
// and the connection deadline.
func tftpSend(conn net.Conn, b []byte) error {
	// the connection deadline (set from the context) still bounds the
	// write; this is only the exchange timeout
	if err := conn.SetWriteDeadline(time.Now().Add(tftpExchangeTO)); err != nil {
		return err
	}
	_, err := conn.Write(b)
	return err
}

func tftpError(n int, b []byte) error {
	if n < 6 {
		return fmt.Errorf("error: short packet")
	}
	code := binary.BigEndian.Uint16(b[2:4])
	msg := ""
	if n > 6 && b[n-1] == 0 {
		msg = string(b[4 : n-1])
	}
	return fmt.Errorf("error %d: %s", code, msg)
}
