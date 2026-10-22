//go:build windows

package atomicfile

import (
	"io/fs"
	"os"

	"golang.org/x/sys/windows"
)

// copyMetadata carries the existing file's DACL (and its protected flag) to the
// temp file, so replacing a file does not reset its access control to whatever
// the directory would inherit. Owner/group are left to the creating token.
func copyMetadata(target string, old fs.FileInfo, tmp *os.File, tmpName string) error {
	sd, err := windows.GetNamedSecurityInfo(target, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION)
	if ctrl, _, cerr := sd.Control(); cerr == nil && ctrl&windows.SE_DACL_PROTECTED != 0 {
		info |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		info |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	return windows.SetNamedSecurityInfo(tmpName, windows.SE_FILE_OBJECT, info, nil, nil, dacl, nil)
}

// replace renames with MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH, so the
// rename is flushed to disk before returning (the Windows stand-in for fsync of
// the directory).
func replace(from, to string) error {
	f, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	t, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(f, t, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

func syncDir(dir string) error { return nil }
