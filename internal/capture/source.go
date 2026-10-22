package capture

import (
	"errors"
	"fmt"
	"io"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// ErrUnsupported is returned by OpenInterface on platforms without a raw
// capture implementation. On Windows this is the documented gap: reading raw
// packets there needs either a driver (Npcap / WinPcap, which Phylax does not
// ship) or a SIO_RCVALL raw socket, which sees IP packets only and has the
// coverage questions listed in docs/capture.md. Windows agents therefore take
// flows from the connection table and transactions from logs until T26 settles
// the raw-socket approach. The Engine and parsers are platform independent and
// already accept LinkTypeRaw input for that socket.
var ErrUnsupported = errors.New("capture: raw packet capture is not implemented on this platform")

// SourceStats are counters kept by a packet source.
type SourceStats struct {
	Packets uint64 // delivered to the caller
	Drops   uint64 // dropped by the kernel before delivery
}

// Source produces packets. ReadPackets blocks for a short interval (so the
// caller can check for shutdown) and invokes fn for each packet available;
// data is only valid inside fn. It returns io.EOF when a finite source ends
// and nil when the wait elapsed or a batch was delivered.
type Source interface {
	LinkType() layers.LinkType
	ReadPackets(fn func(ci gopacket.CaptureInfo, data []byte)) error
	Stats() SourceStats
	Close() error
}

// InterfaceOptions configure live capture. There is deliberately no
// promiscuous-mode option: a host agent records its own traffic.
type InterfaceOptions struct {
	Name       string // interface name; "" captures on all interfaces
	Filter     Filter // kernel filter and snap lengths
	BlockSize  int    // TPACKET_V3 block bytes (page multiple); default 1 MiB
	BlockCount int    // blocks in the mapped ring; default 8
	FrameSize  int    // default 2048
	RetireMS   int    // block retire timeout; default 60 ms
}

type pcapSource struct {
	r    *pcapgo.Reader
	link layers.LinkType
	n    uint64
}

// NewPCAPSource replays a pcap stream as a Source (fixtures, offline analysis
// of a pulled slice).
func NewPCAPSource(r io.Reader) (Source, error) {
	pr, err := pcapgo.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("capture: read pcap: %w", err)
	}
	return &pcapSource{r: pr, link: pr.LinkType()}, nil
}

func (s *pcapSource) LinkType() layers.LinkType { return s.link }
func (s *pcapSource) Stats() SourceStats        { return SourceStats{Packets: s.n} }
func (s *pcapSource) Close() error              { return nil }

func (s *pcapSource) ReadPackets(fn func(gopacket.CaptureInfo, []byte)) error {
	for i := 0; i < 256; i++ {
		data, ci, err := s.r.ZeroCopyReadPacketData()
		if err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return io.EOF
			}
			return err
		}
		s.n++
		fn(ci, data)
	}
	return nil
}
