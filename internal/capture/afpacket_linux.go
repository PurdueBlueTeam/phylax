//go:build linux

package capture

import (
	"encoding/binary"
	"net"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// AF_PACKET capture, no libpcap: one v2 PACKET_MMAP receive ring per
// interface.
//
// Kernel 7.0 changed the tpacket3 ABI (48-byte block descriptors, new
// per-packet headers), so the capture path uses tpacket2: the frame
// grid and the 32-byte per-frame header are ABI-stable across
// kernel generations, which is what a competition lab spanning VM
// images needs. Frame layout (tpacket2_hdr, offsets in bytes):
//
//	status  u32 @0    0 = empty, non-zero = filled
//	len     u32 @4
//	snaplen u32 @8
//	mac     u16 @12   offset of the L2 header within the frame
//	net     u16 @14   offset of the network header within the frame
//
// Packet bytes: frame[mac : mac+len]. A filled frame is released by
// writing TP_STATUS_KERNEL (0) back to the status word.
//
// On kernel 7.0 PACKET_VERSION must be set BEFORE bind; the version
// enum is {V1:0, V2:1, V3:2}.
const (
	ETH_P_ALL        = 0x0003
	packetVersion    = 10 // SOL_PACKET option; absent from x/sys
	tpacketV2        = 1  // enum tpacket_versions
	afpBlockNR       = 4
	afpBlockSize     = 64 * 1024
	afpFrameSize     = 8192
	afpFramesPerBlk  = afpBlockSize / afpFrameSize
	afpFrameNR       = afpBlockNR * afpFramesPerBlk
)

// afpRing is a v2 PACKET_MMAP receive ring on one interface.
type afpRing struct {
	fd  int
	mem []byte
}

// openAFPacket opens an AF_PACKET raw socket on ifname with a kernel
// BPF filter (built in Go from the manifest) and maps the v2 receive
// ring. The ring is a transient capture buffer; the on-disk packet
// ring (ring.go) is the evidence store.
func openAFPacket(ifname string, prog []unix.SockFilter) (*afpRing, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(ETH_P_ALL)))
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*afpRing, error) {
		unix.Close(fd)
		return nil, err
	}
	ver := tpacketV2
	if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, packetVersion, ver); err != nil {
		return fail(err)
	}
	if ifname != "" {
		ifi, err := net.InterfaceByName(ifname)
		if err != nil {
			return fail(err)
		}
		var saddr unix.SockaddrLinklayer
		saddr.Protocol = htons(ETH_P_ALL)
		saddr.Ifindex = ifi.Index
		if err := unix.Bind(fd, &saddr); err != nil {
			return fail(err)
		}
	}
	if len(prog) > 0 {
		if err := setsockoptAttachFilter(fd, prog); err != nil {
			return fail(err)
		}
	}
	req := struct {
		blockSize, blockNR, frameSize, frameNR uint32
	}{afpBlockSize, afpBlockNR, afpFrameSize, afpFrameNR}
	b := unsafe.Slice((*byte)(unsafe.Pointer(&req)), 16)
	if err := unix.SetsockoptString(fd, unix.SOL_PACKET, unix.PACKET_RX_RING, string(b)); err != nil {
		return fail(err)
	}
	size := afpBlockNR * afpBlockSize
	mem, err := unix.Mmap(fd, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return fail(err)
	}
	return &afpRing{fd: fd, mem: mem}, nil
}

func (r *afpRing) close() {
	unix.Munmap(r.mem)
	unix.Close(r.fd)
}

// Read waits up to timeout for captured frames and delivers each
// completed frame (L2 start, full length) to fn. Frames are copied
// out and released before fn runs, so fn may hold the data. Returns
// the number of frames delivered.
func (r *afpRing) Read(timeout time.Duration, fn func(frame []byte)) (int, error) {
	ms := int(timeout / time.Millisecond)
	if ms < 1 {
		ms = 1
	}
	pfds := []unix.PollFd{{Fd: int32(r.fd), Events: unix.POLLIN}}
	n, err := unix.Poll(pfds, ms)
	if err != nil && err != unix.EINTR {
		return 0, err
	}
	got := 0
	if n > 0 || true { // drain whatever is ready; the poll timeout also
		for i := 0; i < afpFrameNR; i++ { // bounds finishFlows cadence
			slot := i * afpFrameSize
			status := binary.LittleEndian.Uint32(r.mem[slot:])
			if status == 0 {
				continue
			}
			length := binary.LittleEndian.Uint32(r.mem[slot+4:])
			mac := int(binary.LittleEndian.Uint16(r.mem[slot+12:]))
			if length > uint32(afpFrameSize-mac) {
				length = uint32(afpFrameSize - mac)
			}
			data := make([]byte, length)
			copy(data, r.mem[slot+mac:slot+mac+int(length)])
			binary.LittleEndian.PutUint32(r.mem[slot:], 0) // TP_STATUS_KERNEL
			fn(data)
			got++
		}
	}
	return got, nil
}

func htons(v uint16) uint16 {
	return binary.BigEndian.Uint16([]byte{byte(v >> 8), byte(v)})
}
