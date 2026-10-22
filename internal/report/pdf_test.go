package report

import (
	"strings"
	"testing"
)

func TestPDFRoundTrip(t *testing.T) {
	md := "# Incident Report 3\n\nTo: Red Team Lead\n\n## 1. SUMMARY\n- webshell at /var/www/html/x.php\n\n| time | event |\n|---|---|\n| 09:32 CDT | beacon to 198.51.100.7 |\n\n```\nsha256sum x.php\n```\n"
	b, err := MarkdownToPDF(md, PDFOptions{Title: "t"})
	if err != nil {
		t.Fatal(err)
	}
	pages, err := ExtractText(b)
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(pages, "\n")
	t.Log(all)
	for _, want := range []string{"Incident Report 3", "198.51.100.7", "sha256sum", "webshell"} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in %q", want, all)
		}
	}
}
