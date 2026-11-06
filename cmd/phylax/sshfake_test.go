package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// sshFakeCmd is one exec request the fake server saw.
type sshFakeCmd struct {
	cmd   string
	stdin []byte
}

// sshFake is a minimal in-process SSH server for the enroll pusher tests.
type sshFake struct {
	user     string
	pass     string
	hostname string

	mu       sync.Mutex
	cmds     []sshFakeCmd
	uploaded []byte
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
		var stdin []byte
		var decoded []byte
		if strings.Contains(p.Command, "base64 -d") {
			stdin, _ = io.ReadAll(ch)
			decoded, _ = base64.StdEncoding.DecodeString(strings.ReplaceAll(string(stdin), "\n", ""))
		}
		f.mu.Lock()
		f.cmds = append(f.cmds, sshFakeCmd{cmd: p.Command, stdin: stdin})
		if strings.Contains(p.Command, "base64 -d") && !strings.Contains(p.Command, "boot.json") && !strings.Contains(p.Command, "name.key") {
			f.uploaded = decoded
		}
		f.mu.Unlock()
		switch {
		case strings.Contains(p.Command, "base64 -d"):
		case strings.HasPrefix(p.Command, "sha256sum "):
			f.mu.Lock()
			sum := sha256.Sum256(f.uploaded)
			f.mu.Unlock()
			io.WriteString(ch, hex.EncodeToString(sum[:])+"  "+strings.TrimSpace(strings.TrimPrefix(p.Command, "sha256sum "))+"\n")
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

func (f *sshFake) commands() []sshFakeCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]sshFakeCmd(nil), f.cmds...)
}
