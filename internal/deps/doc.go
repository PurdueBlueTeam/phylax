// Package deps discovers service dependencies from network traffic (design:
// "Service dependency discovery").
//
// Agent side: Collector attributes outbound connections to the listening
// service whose process tree made them and aggregates them per
// (service, destination) into bounded deps.edge events, with request-driven
// versus background evidence; it also aggregates inbound peers per service
// (deps.peer). Controller side: Graph joins both ends across agents into a
// service dependency graph with confidence and evidence; Propose turns it
// into depends_on additions for operator approval; CheckManifest and
// CheckHostPolicy are the scoring-safety lint.
package deps

// Event kinds emitted by the agent collector.
const (
	KindEdge     = "deps.edge"      // outbound dependency of a local service
	KindEdgeGone = "deps.edge_gone" // a learned dependency stopped appearing
	KindPeer     = "deps.peer"      // inbound peer of a local service
)

// Evidence strengths.
const (
	StrengthStrong = "strong" // opened while an inbound request to the service was active
	StrengthWeak   = "weak"   // background or periodic only
)
