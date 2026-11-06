package plan

// ExpandTemplate substitutes ${name} parameters in every node's target and in
// every string inside Params (recursing into maps and slices).
func ExpandTemplate(p Plan, params map[string]string) (Plan, error) {
	panic("unimplemented: W1 Task 22")
}

// BlockFor returns the agent config block for a module name.
func BlockFor(cfg *AgentConfig, name string) (block any, ok bool) {
	panic("unimplemented: W1 Task 12")
}
