package actions

// deceptionActions are the deception actions (honey files and accounts, the
// decoy listener check). Core registers them.
func deceptionActions() []Action {
	return []Action{filePlant{}, adHoneyAccount{}, decoyCheck{}}
}
