package link

import "github.com/PurdueBlueTeam/phylax/internal/event"

// Priority is the wire send priority; the sender drains strictly lowest first.
type Priority uint8

const (
	PrioCritical  Priority = iota // heartbeats, alerts, acks, dead-man confirmations
	PrioStep                      // plan steps and step results
	PrioEvidence                  // evidence attached to alerts
	PrioFlow                      // transactions and flows
	PrioTelemetry                 // other telemetry
	PrioBulk                      // pcap slices, files, binaries (token bucket)
	NumPriorities
)

// DefaultPriority is the priority a message type is sent at unless the caller
// knows better (event batches are classified by their events, see EventPriority).
func DefaultPriority(m Message) Priority {
	switch m.MsgType() {
	case TypeHeartbeat, TypeAck, TypeHello, TypeWelcome, TypeControl, TypeChunkHave:
		return PrioCritical
	case TypeStep, TypeStepResult, TypeConfig, TypeFetch, TypeRelayRequest, TypeTokenIssue:
		return PrioStep
	case TypeChunk:
		return PrioBulk
	case TypeEvents:
		return PrioTelemetry
	}
	return PrioTelemetry
}

// EventPriority maps an event's shipping priority to a wire priority.
func EventPriority(p event.Priority) Priority {
	switch p {
	case event.PriorityCritical:
		return PrioCritical
	case event.PriorityHigh:
		return PrioFlow
	case event.PriorityNormal:
		return PrioTelemetry
	}
	return PrioBulk
}
