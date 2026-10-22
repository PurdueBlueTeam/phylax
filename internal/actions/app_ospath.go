package actions

import (
	"errors"
	"strings"
)

// osPathParam is an absolute path on either OS family (POSIX, drive or UNC),
// for edits whose target host may run Windows.
var osPathParam = ParamSpec{Name: "path", Type: String, Required: true, Max: 1024, Check: func(v any) error { return checkOSPath(v.(string)) }}

func checkOSPath(s string) error {
	if strings.ContainsRune(s, 0) || !IsAbsPath(s) {
		return errors.New("path must be absolute")
	}
	return nil
}
