package checks

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// maxHTTPBody caps the body size fetched for hashing.
const maxHTTPBody = 16 << 20

// runHTTP fetches the URL and reports the status and the sha256 of the
// normalized body (trailing whitespace trimmed, optional strip_re regexes
// applied first so e.g. rotating timestamps do not flap the check).
func runHTTP(ctx context.Context, ck Check) (map[string]any, error) {
	url, err := pstr(ck.Params, "url")
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("http: %v", err)
	}
	client := &http.Client{} // timeout comes from ctx
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPBody))
	if err != nil {
		return nil, fmt.Errorf("http: %v", err)
	}
	body = normalizeHTTPBody(body, pstrs(ck.Params, "strip_re"))
	actual := map[string]any{
		"status":         resp.StatusCode,
		"content_sha256": sha256Hex(body),
	}
	return actual, nil
}

func normalizeHTTPBody(body []byte, strip []string) []byte {
	out := string(body)
	for _, re := range strip {
		r, err := regexp.Compile(re)
		if err != nil {
			continue
		}
		out = r.ReplaceAllString(out, "")
	}
	return []byte(strings.TrimRight(out, " \t\r\n"))
}
