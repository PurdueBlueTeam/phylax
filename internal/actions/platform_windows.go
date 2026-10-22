//go:build windows

package actions

func defaultAccounts(string) AccountBackend { return &NetAccounts{} }
func defaultServices() ServiceManager       { return &SCM{} }
