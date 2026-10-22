// Package report renders the IR drafter and the inject kit (design: "IR
// drafter" and "Inject kit"). Both produce Markdown and a text-extractable
// PDF from one document model, in pure Go (go-pdf/fpdf with the Go TrueType
// fonts embedded), so the controller needs no external typesetter. Times are
// US Central; file names follow incidentNN_teamTT.pdf / injectNN_teamTT.pdf.
package report

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/go-pdf/fpdf"
	"golang.org/x/image/font/gofont/gobold"
	"golang.org/x/image/font/gofont/gomono"
	"golang.org/x/image/font/gofont/gomonobold"
	"golang.org/x/image/font/gofont/goregular"
)

// PDFOptions tune rendering.
type PDFOptions struct {
	Title string
	// EmbedImages embeds PNG/JPEG figures referenced as ![caption](path) when
	// the file exists. Figures are always captioned in text either way.
	EmbedImages bool
	// BaseDir resolves relative image paths.
	BaseDir string
	// MaxImageBytes bounds one embedded image (default 8 MiB).
	MaxImageBytes int64
}

var (
	reImg     = regexp.MustCompile(`^!\[(.*)\]\((.*)\)\s*$`)
	reBullet  = regexp.MustCompile(`^(\s*)[-*]\s+(.*)$`)
	reSepRow  = regexp.MustCompile(`^\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$`)
	reInlineB = regexp.MustCompile(`\*\*([^*]+)\*\*`)
)

// sanitize maps runes the embedded fonts cannot draw to safe substitutes.
func sanitize(s string) string {
	r := strings.NewReplacer("→", "->", "←", "<-", "✓", "[x]", "✗", "[ ]", "•", "-", "…", "...", "\t", "    ")
	s = r.Replace(s)
	var b strings.Builder
	for _, c := range s {
		switch {
		case c == '\n':
			b.WriteRune(c)
		case c < 32 || c == 0x7f:
		case c <= 0x24F, c == 0x2013, c == 0x2014, c == 0x2018, c == 0x2019, c == 0x201C, c == 0x201D:
			b.WriteRune(c)
		default:
			b.WriteRune('?')
		}
	}
	return b.String()
}

func stripInline(s string) string {
	s = reInlineB.ReplaceAllString(s, "$1")
	return strings.ReplaceAll(s, "`", "")
}

func splitRow(line string) []string {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "|")
	line = strings.TrimSuffix(line, "|")
	parts := strings.Split(line, "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(stripInline(parts[i]))
	}
	return parts
}

// MarkdownToPDF renders the Markdown subset the drafters emit (headings,
// paragraphs, bullets, fenced code, pipe tables, figures) to a PDF whose text
// is extractable (embedded TrueType font with a ToUnicode map).
func MarkdownToPDF(md string, o PDFOptions) ([]byte, error) {
	if o.MaxImageBytes <= 0 {
		o.MaxImageBytes = 8 << 20
	}
	p := fpdf.New("P", "mm", "Letter", "")
	p.SetMargins(18, 18, 18)
	p.SetAutoPageBreak(true, 18)
	p.AddUTF8FontFromBytes("body", "", goregular.TTF)
	p.AddUTF8FontFromBytes("body", "B", gobold.TTF)
	p.AddUTF8FontFromBytes("mono", "", gomono.TTF)
	p.AddUTF8FontFromBytes("mono", "B", gomonobold.TTF)
	p.SetTitle(sanitize(o.Title), true)
	p.SetCreator("phylax", true)
	p.SetCompression(true)
	p.AliasNbPages("{nb}")
	p.SetFooterFunc(func() {
		p.SetY(-12)
		p.SetFont("body", "", 8)
		p.SetTextColor(90, 90, 90)
		p.CellFormat(0, 6, fmt.Sprintf("Page %d of {nb}", p.PageNo()), "", 0, "C", false, 0, "")
		p.SetTextColor(0, 0, 0)
	})
	p.AddPage()
	w := func() float64 { l, _, r, _ := p.GetMargins(); pw, _ := p.GetPageSize(); return pw - l - r }

	lines := strings.Split(strings.ReplaceAll(md, "\r\n", "\n"), "\n")
	inCode := false
	for i := 0; i < len(lines); i++ {
		ln := lines[i]
		trim := strings.TrimSpace(ln)
		if strings.HasPrefix(trim, "```") {
			inCode = !inCode
			if inCode {
				p.Ln(1)
			}
			continue
		}
		if inCode {
			p.SetFont("mono", "", 8)
			p.SetFillColor(244, 244, 244)
			p.MultiCell(w(), 4, sanitize(ln), "", "L", true)
			continue
		}
		switch {
		case trim == "":
			p.Ln(2.5)
		case strings.HasPrefix(trim, "### "):
			p.Ln(1)
			p.SetFont("body", "B", 11)
			p.MultiCell(w(), 5.5, sanitize(stripInline(trim[4:])), "", "L", false)
		case strings.HasPrefix(trim, "## "):
			p.Ln(2)
			p.SetFont("body", "B", 12.5)
			p.MultiCell(w(), 6, sanitize(stripInline(trim[3:])), "", "L", false)
			p.Ln(0.5)
		case strings.HasPrefix(trim, "# "):
			p.SetFont("body", "B", 16)
			p.MultiCell(w(), 8, sanitize(stripInline(trim[2:])), "", "L", false)
			p.Ln(1)
		case strings.HasPrefix(trim, "|"):
			var rows [][]string
			j := i
			for ; j < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[j]), "|"); j++ {
				if reSepRow.MatchString(strings.TrimSpace(lines[j])) {
					continue
				}
				rows = append(rows, splitRow(lines[j]))
			}
			i = j - 1
			drawTable(p, rows, w())
			p.Ln(2)
		case reImg.MatchString(trim):
			m := reImg.FindStringSubmatch(trim)
			figure(p, m[1], m[2], o, w())
		case reBullet.MatchString(ln):
			m := reBullet.FindStringSubmatch(ln)
			indent := float64(len(m[1])) * 1.5
			p.SetFont("body", "", 10)
			p.SetX(18 + indent)
			p.MultiCell(w()-indent, 4.8, sanitize("- "+stripInline(m[2])), "", "L", false)
		default:
			p.SetFont("body", "", 10)
			p.MultiCell(w(), 4.8, sanitize(stripInline(ln)), "", "L", false)
		}
	}
	if err := p.Error(); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := p.Output(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func figure(p *fpdf.Fpdf, caption, path string, o PDFOptions, width float64) {
	if o.EmbedImages && path != "" {
		full := path
		if !filepath.IsAbs(full) && o.BaseDir != "" {
			full = filepath.Join(o.BaseDir, full)
		}
		ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(full), "."))
		if ext == "jpg" {
			ext = "jpeg"
		}
		if st, err := os.Stat(full); err == nil && st.Size() <= o.MaxImageBytes && (ext == "png" || ext == "jpeg") {
			info := p.RegisterImageOptions(full, fpdf.ImageOptions{ImageType: ext, ReadDpi: true})
			if p.Error() == nil && info != nil {
				iw, ih := info.Extent()
				h := width * ih / iw
				if h > 110 {
					h = 110
					width = h * iw / ih
				}
				if p.GetY()+h > 250 {
					p.AddPage()
				}
				p.ImageOptions(full, p.GetX(), p.GetY(), width, 0, false, fpdf.ImageOptions{ImageType: ext, ReadDpi: true}, 0, "")
				p.Ln(h + 1)
			} else {
				p.ClearError()
			}
		}
	}
	p.SetFont("body", "B", 9)
	p.MultiCell(width, 4.4, sanitize(caption), "", "L", false)
	p.SetFont("mono", "", 7.5)
	p.SetTextColor(90, 90, 90)
	p.MultiCell(width, 3.8, sanitize("file: "+path), "", "L", false)
	p.SetTextColor(0, 0, 0)
	p.Ln(1.5)
}

func drawTable(p *fpdf.Fpdf, rows [][]string, width float64) {
	if len(rows) == 0 {
		return
	}
	n := 0
	for _, r := range rows {
		if len(r) > n {
			n = len(r)
		}
	}
	// Column widths proportional to the longest cell (bounded), min 12 mm.
	weights := make([]float64, n)
	for _, r := range rows {
		for c := range r {
			l := float64(len([]rune(r[c])))
			if l > 40 {
				l = 40
			}
			if l < 4 {
				l = 4
			}
			if l > weights[c] {
				weights[c] = l
			}
		}
	}
	var sum float64
	for _, x := range weights {
		sum += x
	}
	cw := make([]float64, n)
	for c := range cw {
		cw[c] = width * weights[c] / sum
		if cw[c] < 12 {
			cw[c] = 12
		}
	}
	var tot float64
	for _, x := range cw {
		tot += x
	}
	for c := range cw {
		cw[c] *= width / tot
	}
	const lh = 4.0
	for ri, r := range rows {
		style := ""
		if ri == 0 {
			style = "B"
		}
		p.SetFont("body", style, 8)
		cells := make([][]string, n)
		maxl := 1
		for c := 0; c < n; c++ {
			txt := ""
			if c < len(r) {
				txt = sanitize(r[c])
			}
			ls := p.SplitText(txt, cw[c]-2)
			if len(ls) == 0 {
				ls = []string{""}
			}
			cells[c] = []string{}
			for _, l := range ls {
				cells[c] = append(cells[c], string(l))
			}
			if len(ls) > maxl {
				maxl = len(ls)
			}
		}
		h := float64(maxl)*lh + 1.5
		if p.GetY()+h > 262 {
			p.AddPage()
		}
		x, y := p.GetX(), p.GetY()
		if ri == 0 {
			p.SetFillColor(228, 232, 238)
		}
		for c := 0; c < n; c++ {
			p.Rect(x, y, cw[c], h, map[bool]string{true: "DF", false: "D"}[ri == 0])
			p.SetXY(x+1, y+0.75)
			p.MultiCell(cw[c]-2, lh, strings.Join(cells[c], "\n"), "", "L", false)
			x += cw[c]
		}
		p.SetXY(18, y+h)
	}
}
