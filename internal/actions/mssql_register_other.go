//go:build !linux

package actions

// sql.query is registered with the Linux family on Linux; on the Windows
// SQL Server host it must exist too (engine mssql).
func init() { Register(func() []Action { return []Action{sqlQuery{}} }) }
