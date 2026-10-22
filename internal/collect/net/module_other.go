//go:build !linux

package netmod

import (
	"context"
	"errors"
	"log/slog"
)

func defaultSources(Config) (SockSource, ProcResolver, error) {
	return nil, nil, errors.New("netmod: linux only")
}

func startNFLog(context.Context, []uint16, *slog.Logger) (<-chan NFLogPacket, error) {
	return nil, errors.New("netmod: linux only")
}

type lockedProcs struct{ inner ProcResolver }

func (l *lockedProcs) Resolve(in []uint64) map[uint64]Proc { return l.inner.Resolve(in) }
