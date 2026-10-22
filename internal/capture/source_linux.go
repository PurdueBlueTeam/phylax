//go:build linux

package capture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

const (
	ethPAll      = 0x0003
	tpStatusUser = 1
	blockDescHdr = 8 // block_status offset within tpacket_block_desc
)

type afpacket struct {
	fd        int
	ring      []byte
	blockSize int
	blockNr   int
	cur       int
	pollMS    int
	packets   atomic.Uint64
	drops     atomic.Uint64
	closed    atomic.Bool
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// OpenInterface opens an AF_PACKET TPACKET_V3 memory-mapped ring on the named
// interface (or all interfaces if Name is empty), with the kernel filter
// attached before the socket is bound so no unfiltered packet is ever
// queued. It needs CAP_NET_RAW. The socket is not put in promiscuous mode.
func OpenInterface(o InterfaceOptions) (Source, error) {
	if o.BlockSize == 0 {
		o.BlockSize = 1 << 20
	}
	if o.BlockCount == 0 {
		o.BlockCount = 8
	}
	if o.FrameSize == 0 {
		o.FrameSize = 2048
	}
	if o.RetireMS == 0 {
		o.RetireMS = 60
	}
	ps := unix.Getpagesize()
	if o.BlockSize%ps != 0 || o.BlockSize%o.FrameSize != 0 || o.FrameSize < 2048 || o.FrameSize%16 != 0 {
		return nil, fmt.Errorf("capture: block size %d / frame size %d not valid (page %d)", o.BlockSize, o.FrameSize, ps)
	}
	var prog []bpf.RawInstruction
	if len(o.Filter.Ports) > 0 || o.Filter.OnlyScored || len(o.Filter.Exclude) > 0 {
		var err error
		if prog, err = o.Filter.Raw(); err != nil {
			return nil, err
		}
	}
	ifindex := 0
	if o.Name != "" {
		ifc, err := net.InterfaceByName(o.Name)
		if err != nil {
			return nil, fmt.Errorf("capture: %w", err)
		}
		ifindex = ifc.Index
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("capture: AF_PACKET socket (needs CAP_NET_RAW): %w", err)
	}
	s := &afpacket{fd: fd, blockSize: o.BlockSize, blockNr: o.BlockCount, pollMS: 100}
	fail := func(what string, err error) (Source, error) {
		s.Close()
		return nil, fmt.Errorf("capture: %s: %w", what, err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_VERSION, unix.TPACKET_V3); err != nil {
		return fail("PACKET_VERSION", err)
	}
	req := unix.TpacketReq3{
		Block_size:     uint32(o.BlockSize),
		Block_nr:       uint32(o.BlockCount),
		Frame_size:     uint32(o.FrameSize),
		Frame_nr:       uint32(o.BlockSize / o.FrameSize * o.BlockCount),
		Retire_blk_tov: uint32(o.RetireMS),
	}
	if err := unix.SetsockoptTpacketReq3(fd, unix.SOL_PACKET, unix.PACKET_RX_RING, &req); err != nil {
		return fail("PACKET_RX_RING", err)
	}
	s.ring, err = unix.Mmap(fd, 0, o.BlockSize*o.BlockCount, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return fail("mmap", err)
	}
	if len(prog) > 0 {
		fp := unix.SockFprog{Len: uint16(len(prog)), Filter: (*unix.SockFilter)(unsafe.Pointer(&prog[0]))}
		if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &fp); err != nil {
			return fail("SO_ATTACH_FILTER", err)
		}
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(ethPAll), Ifindex: ifindex}); err != nil {
		return fail("bind", err)
	}
	return s, nil
}

func (s *afpacket) LinkType() layers.LinkType { return layers.LinkTypeEthernet }

// Live marks a source whose packet timestamps follow the wall clock.
func (s *afpacket) Live() bool { return true }

func (s *afpacket) Stats() SourceStats {
	if !s.closed.Load() {
		if v, err := unix.GetsockoptTpacketStatsV3(s.fd, unix.SOL_PACKET, unix.PACKET_STATISTICS); err == nil {
			s.drops.Add(uint64(v.Drops)) // the kernel resets its counters on every read
		}
	}
	return SourceStats{Packets: s.packets.Load(), Drops: s.drops.Load()}
}

func (s *afpacket) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	var err error
	if s.ring != nil {
		err = unix.Munmap(s.ring)
		s.ring = nil
	}
	if e := unix.Close(s.fd); err == nil {
		err = e
	}
	return err
}

func (s *afpacket) blockStatus(b []byte) *uint32 {
	return (*uint32)(unsafe.Pointer(&b[blockDescHdr]))
}

// The ring headers are in host byte order.
func le32(b []byte, o int) uint32 { return binary.NativeEndian.Uint32(b[o:]) }
func le16(b []byte, o int) uint16 { return binary.NativeEndian.Uint16(b[o:]) }

// ReadPackets waits up to ~100 ms for a retired block and delivers its packets.
func (s *afpacket) ReadPackets(fn func(gopacket.CaptureInfo, []byte)) error {
	if s.closed.Load() {
		return errors.New("capture: source closed")
	}
	blk := func() []byte { return s.ring[s.cur*s.blockSize : (s.cur+1)*s.blockSize] }
	if atomic.LoadUint32(s.blockStatus(blk()))&tpStatusUser == 0 {
		fds := []unix.PollFd{{Fd: int32(s.fd), Events: unix.POLLIN | unix.POLLERR}}
		n, err := unix.Poll(fds, s.pollMS)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				return nil
			}
			return fmt.Errorf("capture: poll: %w", err)
		}
		if n == 0 || atomic.LoadUint32(s.blockStatus(blk()))&tpStatusUser == 0 {
			return nil
		}
	}
	for i := 0; i < s.blockNr; i++ {
		b := blk()
		if atomic.LoadUint32(s.blockStatus(b))&tpStatusUser == 0 {
			break
		}
		s.deliverBlock(b, fn)
		atomic.StoreUint32(s.blockStatus(b), 0) // back to the kernel
		s.cur = (s.cur + 1) % s.blockNr
	}
	return nil
}

func (s *afpacket) deliverBlock(b []byte, fn func(gopacket.CaptureInfo, []byte)) {
	num := int(le32(b, 12))
	off := int(le32(b, 16))
	var tagged []byte
	for i := 0; i < num; i++ {
		if off < 0 || off+48 > len(b) {
			return
		}
		h := b[off:]
		sec, nsec := le32(h, 4), le32(h, 8)
		snap, wire := int(le32(h, 12)), int(le32(h, 16))
		status := le32(h, 20)
		mac := int(le16(h, 24))
		if mac < 0 || mac+snap > len(h) {
			return
		}
		data := h[mac : mac+snap]
		if status&unix.TP_STATUS_VLAN_VALID != 0 && snap >= 12 {
			// The kernel stripped the 802.1Q tag into metadata; put it back so
			// pcap output and the decoder see what was on the wire.
			tci := le32(h, 32)
			tpid := le16(h, 36)
			if tpid == 0 {
				tpid = 0x8100
			}
			tagged = append(tagged[:0], data[:12]...)
			tagged = append(tagged, byte(tpid>>8), byte(tpid), byte(tci>>8), byte(tci))
			tagged = append(tagged, data[12:]...)
			data = tagged
			wire += 4
		}
		ci := gopacket.CaptureInfo{Timestamp: time.Unix(int64(sec), int64(nsec)), CaptureLength: len(data), Length: wire}
		s.packets.Add(1)
		fn(ci, data)
		next := int(le32(h, 0))
		if next == 0 {
			return
		}
		off += next
	}
}
