package svcinstall

// New returns the platform installer (systemd).
func New() Installer { return &Systemd{} }
