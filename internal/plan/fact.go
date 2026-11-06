package plan

import "time"

const (
	ControlFact = "fact"
	MaxFactData = 16 << 10
	MaxFactTTL  = 24 * time.Hour
)

// FactSender returns the module that owns a fact subtype.
func FactSender(fact string) (module string, ok bool) { panic("unimplemented: W1 Task 30") }
