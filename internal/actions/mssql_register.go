package actions

func init() {
	registerExtra(func() []Action { return []Action{mssqlAudit{}, mssqlLock{}} })
	registerUndo(kindMSSQLUndo, undoMSSQL)
}
