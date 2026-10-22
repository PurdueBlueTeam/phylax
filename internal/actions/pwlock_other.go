//go:build !unix

package actions

import "context"

func lockFileCross(context.Context, string) (func(), error) { return func() {}, nil }
