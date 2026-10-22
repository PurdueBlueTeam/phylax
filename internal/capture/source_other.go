//go:build !linux

package capture

// OpenInterface is not available here; see ErrUnsupported.
func OpenInterface(InterfaceOptions) (Source, error) { return nil, ErrUnsupported }
