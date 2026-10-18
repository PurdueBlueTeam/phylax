package checks

import (
	"context"
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
)

// runFTP logs in, issues LIST (in `path` when given) and reports the sha256
// of the normalized listing: each line trimmed of trailing whitespace,
// sorted, joined with \n.
func runFTP(ctx context.Context, ck Check) (map[string]any, error) {
	host, err := pstr(ck.Params, "host")
	if err != nil {
		return nil, err
	}
	addr, err := addrWithDefaultPort(host, ck)
	if err != nil {
		return nil, fmt.Errorf("ftp: %v", err)
	}
	conn, err := net.DialTimeout("tcp", addr, dialTimeout(ctx))
	if err != nil {
		return nil, fmt.Errorf("ftp: %v", err)
	}
	defer conn.Close()
	if err := setConnDeadline(conn, ctx); err != nil {
		return nil, fmt.Errorf("ftp: %v", err)
	}
	r := bufio.NewReader(conn)

	code, line, err := ftpRead(r)
	if err != nil || code != 220 {
		return nil, fmt.Errorf("ftp: greeting: %s (%v)", line, err)
	}
	if user := pstrOpt(ck.Params, "user"); user != "" {
		if code, _, err = ftpCmd(r, conn, "USER "+ftpQuote(user)); err != nil || (code != 331 && code != 230) {
			return nil, fmt.Errorf("ftp: USER: code %d (%v)", code, err)
		}
		if code != 230 {
			if code, _, err = ftpCmd(r, conn, "PASS "+ftpQuote(pstrOpt(ck.Params, "pass"))); err != nil || code != 230 {
				return nil, fmt.Errorf("ftp: PASS: code %d (%v)", code, err)
			}
		}
	}
	if path := pstrOpt(ck.Params, "path"); path != "" {
		if code, _, err = ftpCmd(r, conn, "CWD "+ftpQuote(path)); err != nil || code != 250 {
			return nil, fmt.Errorf("ftp: CWD %s: code %d (%v)", path, code, err)
		}
	}

	// PASV, then LIST over the passive data connection.
	if _, line, err = ftpCmd(r, conn, "PASV"); err != nil {
		return nil, fmt.Errorf("ftp: PASV: %v", err)
	}
	dataAddr, err := parsePASV(line)
	if err != nil {
		return nil, fmt.Errorf("ftp: PASV: %v", err)
	}
	dataConn, err := net.DialTimeout("tcp", dataAddr, dialTimeout(ctx))
	if err != nil {
		return nil, fmt.Errorf("ftp: passive data connect: %v", err)
	}
	defer dataConn.Close()

	if code, _, err = ftpCmd(r, conn, "LIST"); err != nil || code != 150 {
		return nil, fmt.Errorf("ftp: LIST: code %d (%v)", code, err)
	}
	listing, _ := io.ReadAll(dataConn) // data conn closes after 226
	if code, _, err = ftpCmd(r, conn); err != nil || code != 226 {
		return nil, fmt.Errorf("ftp: LIST end: code %d (%v)", code, err)
	}
	ftpCmd(r, conn, "QUIT")

	sum := sha256.Sum256([]byte(normalizeFTPList(listing)))
	return map[string]any{"list_sha256": hex.EncodeToString(sum[:])}, nil
}

func ftpQuote(s string) string {
	if strings.ContainsAny(s, " <>|\"") {
		return `"` + strings.ReplaceAll(s, `"`, ``) + `"`
	}
	return s
}

// ftpRead reads one (possibly multi-line) FTP reply.
func ftpRead(r *bufio.Reader) (code int, text string, err error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return 0, strings.TrimSpace(line), err
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) < 4 {
		return 0, line, fmt.Errorf("bad reply %q", line)
	}
	code, err = strconv.Atoi(line[:3])
	if err != nil || (line[3] != ' ' && line[3] != '-') {
		return 0, line, fmt.Errorf("bad reply %q", line)
	}
	text = line
	if line[3] != '-' {
		return code, text, nil
	}
	for { // multi-line: continue until "NNN "
		next, err := r.ReadString('\n')
		if err != nil {
			return code, text, err
		}
		next = strings.TrimRight(next, "\r\n")
		text += "\n" + next
		if len(next) >= 4 && next[:3] == line[:3] && next[3] == ' ' {
			return code, text, nil
		}
	}
}

// ftpCmd sends the given commands (or just reads the pending reply when
// none) and returns the reply code.
func ftpCmd(r *bufio.Reader, w io.Writer, cmds ...string) (int, string, error) {
	for _, cmd := range cmds {
		if _, err := io.WriteString(w, cmd+"\r\n"); err != nil {
			return 0, "", err
		}
	}
	return ftpRead(r)
}

func parsePASV(line string) (string, error) {
	open := strings.IndexByte(line, '(')
	close := strings.IndexByte(line, ')')
	if open < 0 || close < open+1 {
		return "", fmt.Errorf("no passive address in %q", line)
	}
	parts := strings.Split(line[open+1:close], ",")
	if len(parts) != 6 {
		return "", fmt.Errorf("bad passive address in %q", line)
	}
	var nums [6]int
	for i := range 6 {
		n, err := strconv.Atoi(strings.TrimSpace(parts[i]))
		if err != nil {
			return "", fmt.Errorf("bad passive address in %q", line)
		}
		nums[i] = n
	}
	ip := net.IPv4(byte(nums[0]), byte(nums[1]), byte(nums[2]), byte(nums[3]))
	return net.JoinHostPort(ip.String(), strconv.Itoa(nums[4]*256+nums[5])), nil
}

func normalizeFTPList(b []byte) string {
	lines := strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if l = strings.TrimRight(l, " \t\r"); l != "" {
			out = append(out, l)
		}
	}
	sort.Strings(out)
	return strings.Join(out, "\n")
}
