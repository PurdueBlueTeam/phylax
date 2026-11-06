package actions

// The deception actions (honey files and accounts, the decoy listener check)
// join the core catalog through the Register hook.
func init() {
	Register(func() []Action { return []Action{filePlant{}, adHoneyAccount{}, decoyCheck{}} })
}
