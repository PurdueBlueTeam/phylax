package integrity

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// WinbindexOptions control the import of one Winbindex per-file list.
type WinbindexOptions struct {
	// Dirs are the (Windows) directories this file lives in for the builds in
	// play, e.g. `C:\Windows\System32`. Winbindex is keyed by file name, not
	// path, so the importer needs them. Default: \Windows\System32.
	Dirs []string
	OS   string // e.g. "win2022"
	// Signer recorded for signed files (default "Microsoft Windows").
	Signer string
	// MaxEntries bounds the import (default 1,000,000).
	MaxEntries int
}

type winbindexFile struct {
	FileInfo *struct {
		Size          int64  `json:"size"`
		SHA256        string `json:"sha256"`
		Version       string `json:"version"`
		SigningStatus string `json:"signingStatus"`
		SignatureType string `json:"signatureType"`
	} `json:"fileInfo"`
}

// ImportWinbindex reads one Winbindex per-file JSON list (the
// by_filename_compressed/<name>.json[.gz] format: an object keyed by sha256
// whose values carry fileInfo{size,sha256,version,signingStatus,...}) and
// returns ledger entries, one per (hash, directory). Plain or gzip input
// (sniffed) is accepted. The data is fetched and trimmed in CI (D-5); this
// function never touches the network.
func ImportWinbindex(r io.Reader, fileName string, opt WinbindexOptions) ([]Entry, error) {
	if len(opt.Dirs) == 0 {
		opt.Dirs = []string{`C:\Windows\System32`}
	}
	if opt.Signer == "" {
		opt.Signer = "Microsoft Windows"
	}
	if opt.MaxEntries <= 0 {
		opt.MaxEntries = 1_000_000
	}
	dr, closeFn, err := decompress(r, 1<<30)
	if err != nil {
		return nil, fmt.Errorf("integrity: winbindex: %w", err)
	}
	defer closeFn()
	var m map[string]winbindexFile
	if err := json.NewDecoder(dr).Decode(&m); err != nil {
		return nil, fmt.Errorf("integrity: winbindex json: %w", err)
	}
	var out []Entry
	for key, v := range m {
		h := key
		if v.FileInfo != nil && v.FileInfo.SHA256 != "" {
			h = v.FileInfo.SHA256
		}
		sum, err := ParseSum(h)
		if err != nil {
			continue
		}
		var size int64
		var ver, signer string
		if v.FileInfo != nil {
			size, ver = v.FileInfo.Size, v.FileInfo.Version
			if strings.EqualFold(v.FileInfo.SigningStatus, "signed") || v.FileInfo.SignatureType != "" && !strings.EqualFold(v.FileInfo.SignatureType, "none") {
				signer = opt.Signer
			}
		}
		for _, d := range opt.Dirs {
			if len(out) >= opt.MaxEntries {
				return out, errTooBig
			}
			out = append(out, Entry{
				Path: NormalizePath(strings.TrimRight(d, `\/`) + `\` + fileName), SHA256: sum, Size: size,
				Version: ver, Signer: signer, OS: opt.OS, Source: SourceVendorPackage,
			})
		}
	}
	return out, nil
}
