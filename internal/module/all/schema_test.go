package all

import "testing"

func TestModuleSchemasCommitted(t *testing.T) {
	t.Skip("unimplemented: W1 Task 33")
	// for every agent factory with a manifest: block type from plan.BlockFor(&plan.AgentConfig{}, name)
	// for every controller module implementing module.Configurable: ConfigBlock()
	// generate; with -update write manifest/schema/modules/<name>.schema.json; else compare with the file (diff in the error)
}
