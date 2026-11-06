package module

// Register adds a controller module from init. It panics on a duplicate name
// or an invalid manifest.
func Register(m ControllerModule) { panic("unimplemented: W1 Task 7") }

// Registered returns every registered controller module sorted by name.
func Registered() []ControllerModule { panic("unimplemented: W1 Task 7") }

// Lookup returns a registered controller module by name.
func Lookup(name string) (ControllerModule, bool) { panic("unimplemented: W1 Task 7") }
