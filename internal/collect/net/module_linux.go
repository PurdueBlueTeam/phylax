//go:build linux

package netmod

import (
	"context"
	"log/slog"
	"sync"
)

func defaultSources(cfg Config) (SockSource, ProcResolver, error) {
	return SockDiag{WantBytes: cfg.ByteCounters}, &ProcFS{Root: cfg.ProcRoot, HashExe: cfg.HashExe}, nil
}

// startNFLog opens the reader and pumps packets into a bounded channel;
// when it is full packets are dropped (the blocked socket retries anyway).
func startNFLog(ctx context.Context, groups []uint16, log *slog.Logger) (<-chan NFLogPacket, error) {
	r, err := OpenNFLog(groups, 128)
	if err != nil {
		return nil, err
	}
	ch := make(chan NFLogPacket, 1024)
	go func() {
		defer r.Close()
		err := r.Run(ctx, func(p NFLogPacket) {
			select {
			case ch <- p:
			default:
			}
		})
		if ctx.Err() == nil {
			log.Warn("net: nflog reader stopped", "err", err)
		}
	}()
	return ch, nil
}

type lockedProcs struct {
	mu    sync.Mutex
	inner ProcResolver
}

func (l *lockedProcs) Resolve(in []uint64) map[uint64]Proc {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.inner.Resolve(in)
}
