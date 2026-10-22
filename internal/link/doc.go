// Package link implements the Phylax transport: ECDSA identities with
// public-key pinning, a TLS listener that dispatches by ALPN, length-prefixed
// framing with bounded decompression, the typed message codec, and a session
// with strict-priority bounded send queues plus ack/resend for events.
//
// The wire format is specified in docs/protocol.md; this package implements it.
package link
