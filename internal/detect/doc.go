// Package detect is the rule engine (design: "Detection and response").
//
// Rules are YAML documents with a deliberately small language: field
// conditions combined with all/any/not, windowed counts per key, sequences,
// learned baselines (in_profile) and exemption of events that carry a Phylax
// plan tag. Loading is strict: unknown keys, unknown operators, bad regexes
// and empty or dangling list items are errors, never silently match-all.
// Rules are indexed by event kind; regexes compile once at load.
package detect
