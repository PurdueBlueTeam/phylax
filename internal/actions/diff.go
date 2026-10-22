package actions

import (
	"fmt"
	"strings"
)

const maxDiffLines = 2000

// lineDiff renders a simple line diff (LCS) of a and b, bounded.
func lineDiff(a, b string) string {
	if a == b {
		return ""
	}
	al, bl := splitLines(a), splitLines(b)
	if len(al)*len(bl) > 4_000_000 {
		return fmt.Sprintf("(large change: %d -> %d lines, %d -> %d bytes)", len(al), len(bl), len(a), len(b))
	}
	n, m := len(al), len(bl)
	dp := make([][]int32, n+1)
	for i := range dp {
		dp[i] = make([]int32, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if al[i] == bl[j] {
				dp[i][j] = dp[i+1][j+1] + 1
			} else {
				dp[i][j] = max(dp[i+1][j], dp[i][j+1])
			}
		}
	}
	var sb strings.Builder
	lines := 0
	emit := func(prefix, s string) {
		if lines++; lines <= maxDiffLines {
			sb.WriteString(prefix + s + "\n")
		}
	}
	i, j := 0, 0
	for i < n || j < m {
		switch {
		case i < n && j < m && al[i] == bl[j]:
			i++
			j++
		case j < m && (i == n || dp[i][j+1] >= dp[i+1][j]):
			emit("+", bl[j])
			j++
		default:
			emit("-", al[i])
			i++
		}
	}
	if lines > maxDiffLines {
		fmt.Fprintf(&sb, "... %d more changed lines\n", lines-maxDiffLines)
	}
	return sb.String()
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

func isText(b []byte) bool {
	for _, c := range b {
		if c == 0 {
			return false
		}
	}
	return true
}
