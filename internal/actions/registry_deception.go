package actions

// The deception actions (honey files and accounts, the decoy listener check)
// join the core catalog through the registerExtra hook.
func init() {
	registerExtra(func() []Action { return []Action{filePlant{}, adHoneyAccount{}, decoyCheck{}} })
}
