package link

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestFramingRoundtrip(t *testing.T) {
	cases := []struct {
		name string
		body []byte
	}{
		{"small", []byte(`{"a":1}`)},
		{"large-compressible", []byte(strings.Repeat("abcdefgh", 4096))},
		{"empty", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pr, pw := io.Pipe()
			defer pr.Close()
			werr := make(chan error, 1)
			go func() {
				werr <- NewWriter(pw).Write(&Message{Type: TypHeartbeat, Payload: tc.body})
				pw.Close()
			}()
			got, err := NewReader(pr).Read()
			if err != nil {
				t.Fatal(err)
			}
			if err := <-werr; err != nil {
				t.Fatal(err)
			}
			if got.Type != TypHeartbeat || string(got.Payload) != string(tc.body) {
				t.Fatalf("roundtrip mismatch: type=%x payload=%q", got.Type, got.Payload)
			}
		})
	}
}

func TestFramingRejectsOversize(t *testing.T) {
	// 5-byte header with length = MaxMessage+1, no body.
	buf := []byte{0x00, 0x40, 0x00, 0x01, TypHeartbeat}
	_, err := NewReader(strings.NewReader(string(buf))).Read()
	if err == nil {
		t.Fatal("expected error for oversize frame")
	}
}

func TestConnPriorityOrder(t *testing.T) {
	connA, connB := net.Pipe()
	defer connA.Close()
	defer connB.Close()

	var order []byte
	done := make(chan struct{})
	go func() {
		defer close(done)
		rd := NewReader(connB)
		for {
			m, err := rd.Read()
			if err != nil {
				return
			}
			order = append(order, m.Type)
		}
	}()

	c := NewConn(connA, "test")
	defer c.Close()

	// Enqueue out of priority order; the sender must reorder.
	if err := c.Enqueue(PrioBulk, &Message{Type: 0x60, Payload: []byte{1}}); err != nil {
		t.Fatal(err)
	}
	if err := c.Enqueue(PrioCore, &Message{Type: 0x61, Payload: []byte{1}}); err != nil {
		t.Fatal(err)
	}
	if err := c.Enqueue(PrioSteps, &Message{Type: 0x62, Payload: []byte{1}}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(order) < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	connB.Close()
	<-done
	want := []byte{0x61, 0x62, 0x60} // core, steps, bulk
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("send order = %v, want %v", order, want)
	}
}

func TestConnDispatchAndClose(t *testing.T) {
	connA, connB := net.Pipe()
	defer connB.Close()
	c := NewConn(connA, "test")

	got := make(chan *Message, 1)
	c.On(0x63, func(_ context.Context, _ *Conn, m *Message) error {
		got <- m
		return nil
	})

	go func() {
		if err := NewWriter(connB).Write(&Message{Type: 0x63, Payload: []byte("hi")}); err != nil {
			return
		}
	}()
	select {
	case m := <-got:
		if string(m.Payload) != "hi" {
			t.Fatalf("payload = %q", m.Payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for dispatch")
	}
	c.Close()
	select {
	case <-c.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for Done")
	}
}

func TestTLSPinning(t *testing.T) {
	_, srvPriv, err := NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	srvCert, err := SelfSignedCert(srvPriv, "controller")
	if err != nil {
		t.Fatal(err)
	}
	pin := PinCert(srvCert)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srvTLS := tls.NewListener(ln, ServerConfig(srvPriv, srvCert, []string{ALPNAgent}, nil))
	defer srvTLS.Close()

	go func() {
		for {
			conn, err := srvTLS.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(io.Discard, c)
			}(conn)
		}
	}()

	_, clPriv, _ := NewKeyPair()
	clCert, err := SelfSignedCert(clPriv, "agent1")
	if err != nil {
		t.Fatal(err)
	}

	dial := func(pin Pin) error {
		cfg := ClientConfig(clPriv, clCert, pin, []string{ALPNAgent})
		conn, err := tls.Dial("tcp", ln.Addr().String(), cfg)
		if err != nil {
			return err
		}
		conn.Close()
		return nil
	}

	if err := dial(pin); err != nil {
		t.Fatalf("correct pin rejected: %v", err)
	}
	if err := dial(Pin("AAAA" + pin[4:])); err == nil {
		t.Fatal("wrong pin accepted")
	}
	if err := dial(Pin(strings.Repeat("B", len(pin)))); err == nil {
		t.Fatal("garbage pin accepted")
	}
}
