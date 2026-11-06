package bench

// Criteria are the transport envelope's pass figures for a load run.
type Criteria struct {
	LatencyP99Ms  float64 // 10000
	MaxReconnectS float64 // 35
}

// Result is one named pass or fail.
type Result struct {
	Name, Got, Want string
	Pass            bool
}

// Check evaluates the envelope criteria on a load run: recs from the
// controller file and the load file, hostPrefix the synthetic agents.
func Check(recs []Record, hostPrefix string, c Criteria) []Result {
	panic("unimplemented: W14 Task 6")
}
