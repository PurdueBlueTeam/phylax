package actions

func init() {
	Register(func() []Action { return []Action{mssqlAudit{}, mssqlLock{}} })
	RegisterUndo(kindMSSQLUndo, undoMSSQL)
}
