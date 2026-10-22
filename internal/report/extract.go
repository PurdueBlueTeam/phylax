package report

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/ledongthuc/pdf"
)

// ExtractText returns the text of every page of a PDF, the way a reader like
// NISE would see it. An image-only PDF yields empty pages.
func ExtractText(b []byte) (pages []string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("pdf parse: %v", r)
		}
	}()
	r, err := pdf.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return nil, err
	}
	for i := 1; i <= r.NumPage(); i++ {
		pg := r.Page(i)
		if pg.V.IsNull() {
			pages = append(pages, "")
			continue
		}
		rd, err := pg.GetPlainText(nil)
		if err != nil {
			return nil, fmt.Errorf("page %d: %w", i, err)
		}
		pages = append(pages, strings.TrimSpace(fmt.Sprint(rd)))
	}
	return pages, nil
}
