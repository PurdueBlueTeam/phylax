//go:build !linux

package actions

type realAttr struct{}

func (realAttr) Get(string) (uint32, error) { return 0, ErrUnsupported }
func (realAttr) Set(string, uint32) error   { return ErrUnsupported }
