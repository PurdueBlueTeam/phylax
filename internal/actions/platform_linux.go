//go:build linux

package actions

func defaultAccounts(root string) AccountBackend { return &FileAccounts{Root: root} }
func defaultServices() ServiceManager            { return &Systemd{} }
