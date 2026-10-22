// Package injectkit holds the inject templates as data files. They are blank:
// placeholders only, no prepared answers from any past event (the MWCCDC
// repository rule allows document templates, not prepared inject responses).
// internal/report renders them.
package injectkit

import "embed"

// FS contains the *.md.tmpl templates and the README.
//
//go:embed *.tmpl
var FS embed.FS
