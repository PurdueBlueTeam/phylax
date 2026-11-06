package plan

import "time"

const (
	ControlFact = "fact"
	MaxFactData = 16 << 10
	MaxFactTTL  = 24 * time.Hour
)

// factOwners is the closed subtype table: the module that may send each fact.
var factOwners = map[string]string{
	"work_window":         "teamfeed",
	"round_clock":         "scorer",
	"gpo_finding":         "ad",
	"scorer_probe_result": "checks",
	"creds_txn":           "creds",
}

// FactSender returns the module that owns a fact subtype.
func FactSender(fact string) (module string, ok bool) {
	module, ok = factOwners[fact]
	return module, ok
}
