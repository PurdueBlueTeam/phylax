// Package spool is the agent's crash-safe, sequenced, hash-chained local store
// of events awaiting acknowledgment (design: "The spool", "Reliability").
//
// Layout. The spool directory holds one set of segment files per priority
// (files p<prio>-<first seq>.seg), a meta file (meta.json: cumulative ack and
// chain head, replaced atomically) and a lock file. Segments are append-only
// sequences of CRC-checked, length-prefixed frames, each holding one sealed
// event. There is a single hash chain for the agent; sequence numbers are
// global, so the segment sets interleave in sequence order. Keeping priorities
// in separate segments is what allows shedding to drop whole low-priority
// segments without rewriting anything.
//
// Shedding never rewrites the chain: the dropped sequence runs are announced
// by a "spool.gap" event (priority Critical) appended to the chain. Each run
// carries the hash of its last dropped event so a verifier can bridge the
// survivor that follows it.
package spool
