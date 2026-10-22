//go:build !linux

package honeytokens

// NewFanotify is unavailable off Linux; Windows uses SACL auditing (4663).
func NewFanotify() (Watcher, error) { return nil, ErrWatchUnavailable }
