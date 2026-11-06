package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"net"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// sshFake is a minimal in-process SSH server for the enroll pusher tests.
type sshFake struct {
	user     string
	pass     string
	hostname string

	mu   sync.Mutex
	cmds []string
}

func startSSHFake(t *testing.T, f *sshFake) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		if c.User() == f.user && string(pw) == f.pass {
			return nil, nil
		}
		return nil, io.ErrUnexpectedEOF
	}}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					c.Close()
					return
				}
				defer sc.Close()
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					if nc.ChannelType() != "session" {
						nc.Reject(ssh.UnknownChannelType, "no")
						continue
					}
					ch, creqs, err := nc.Accept()
					if err != nil {
						continue
					}
					go f.session(ch, creqs)
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

func (f *sshFake) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	for r := range reqs {
		if r.Type != "exec" {
			r.Reply(false, nil)
			continue
		}
		var p struct{ Command string }
		ssh.Unmarshal(r.Payload, &p)
		r.Reply(true, nil)
		f.mu.Lock()
		f.cmds = append(f.cmds, p.Command)
		f.mu.Unlock()
		switch {
		case strings.Contains(p.Command, "base64 -d"):
			io.Copy(io.Discard, ch)
		case p.Command == "echo PHYLAXOK":
			io.WriteString(ch, "PHYLAXOK\n")
		case p.Command == "hostname -s":
			io.WriteString(ch, f.hostname+"\n")
		case strings.HasPrefix(p.Command, "df -Pk"):
			io.WriteString(ch, "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 100000 1000 99000 2% /\n")
		}
		ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
		ch.Close()
		return
	}
}
