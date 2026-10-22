//go:build windows

package store

// Directory fsync is not supported on Windows; renames are journaled by NTFS.
func syncDir(string) error { return nil }
