package http

import (
	"strings"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/parsers/parsertest"
	"github.com/PurdueBlueTeam/phylax/internal/parsers/txn"
	"github.com/PurdueBlueTeam/phylax/internal/scorer"
)

// The request the Quotient scorer sends (quotient.md section 6).
const quotientReq = "GET /index.php HTTP/1.1\r\nHost: 172.20.240.10:80\r\nUser-Agent: Mozilla/5.0 (Symbian)\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n"
const okResp = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 11\r\nServer: Apache\r\n\r\nhello world"

func TestQuotientRequestClassifiesAsScorer(t *testing.T) {
	out := parsertest.Run(New, parsertest.C2S([]byte(quotientReq)), parsertest.S2C([]byte(okResp)))
	if len(out) != 1 {
		t.Fatalf("got %d txns", len(out))
	}
	x := out[0]
	if x.Attr["http.method"] != "GET" || x.Attr["http.path"] != "/index.php" || x.Attr["http.host"] != "172.20.240.10:80" ||
		x.Attr["http.status"] != "200" || x.Attr["http.resp_body_len"] != "11" {
		t.Fatalf("attrs: %v", x.Attr)
	}
	if x.Attr["http.resp_body_sha256"] != txn.SHA256Hex([]byte("hello world")) {
		t.Fatalf("body hash %s", x.Attr["http.resp_body_sha256"])
	}
	if got := strings.Join(x.List["http.headers"], ","); got != "Host,User-Agent,Accept-Encoding,Connection" {
		t.Fatalf("headers %s", got)
	}
	c, err := scorer.NewClassifier(scorer.DefaultTable())
	if err != nil {
		t.Fatal(err)
	}
	r := c.Classify(x.Features())
	if !r.HasEvidence("http.header_set") || !r.HasEvidence("http.host_port") || r.Verdict == scorer.VerdictNotScorer {
		t.Fatalf("classifier: %+v", r)
	}
	// a browser sends more headers and is contradicted
	br := "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: x\r\nAccept: */*\r\nAccept-Language: en\r\nConnection: keep-alive\r\n\r\n"
	b := parsertest.Run(New, parsertest.C2S([]byte(br)))[0]
	if rb := c.Classify(b.Features()); !rb.HasEvidence("http.extra_headers") || rb.Score >= r.Score {
		t.Fatalf("browser should score lower: %+v vs %+v", rb, r)
	}
}

func TestPipelinedChunkedAndResegmented(t *testing.T) {
	req := "POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nabcde" + "GET /b HTTP/1.1\r\nHost: h\r\n\r\n"
	resp := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nfoo\r\n4;ext=1\r\nbarz\r\n0\r\n\r\n" +
		"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
	steps := []parsertest.Step{parsertest.C2S([]byte(req)), parsertest.S2C([]byte(resp))}
	for _, n := range []int{1, 2, 7, 1000} {
		out := parsertest.Run(New, parsertest.Resegment(steps, n)...)
		if len(out) != 2 {
			t.Fatalf("n=%d got %d txns", n, len(out))
		}
		if out[0].Attr["http.path"] != "/a" || out[0].Attr["http.req_body_sha256"] != txn.SHA256Hex([]byte("abcde")) ||
			out[0].Attr["http.resp_body_sha256"] != txn.SHA256Hex([]byte("foobarz")) || out[0].Attr["http.resp_body_len"] != "7" {
			t.Fatalf("n=%d first: %v", n, out[0].Attr)
		}
		if out[1].Attr["http.path"] != "/b" || out[1].Attr["http.status"] != "404" {
			t.Fatalf("n=%d second: %v", n, out[1].Attr)
		}
	}
}

func TestHeadAndReadUntilClose(t *testing.T) {
	out := parsertest.Run(New,
		parsertest.C2S([]byte("HEAD /x HTTP/1.1\r\nHost: h\r\n\r\n")),
		parsertest.S2C([]byte("HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n")),
	)
	if len(out) != 1 || out[0].Attr["http.status"] != "200" || out[0].Attr["http.resp_body_len"] != "0" {
		t.Fatalf("HEAD: %+v", out)
	}
	out = parsertest.Run(New,
		parsertest.C2S([]byte("GET / HTTP/1.0\r\n\r\n")),
		parsertest.S2C([]byte("HTTP/1.0 200 OK\r\n\r\nbody until close")),
	)
	if len(out) != 1 || out[0].Attr["http.resp_body_len"] != "16" {
		t.Fatalf("read-until-close: %+v", out)
	}
}

func TestBasicAuthIsNeverStored(t *testing.T) {
	// base64("alice:hunter2")
	req := "GET / HTTP/1.1\r\nHost: h\r\nAuthorization: Basic YWxpY2U6aHVudGVyMg==\r\n\r\n"
	out := parsertest.Run(New, parsertest.C2S([]byte(req)))
	x := out[0]
	if x.Cred == nil || x.Cred.User != "alice" || x.Cred.PassHash != txn.HashSecret("hunter2") {
		t.Fatalf("cred %+v", x.Cred)
	}
	for k, v := range x.Attr {
		if strings.Contains(v, "hunter2") || strings.Contains(v, "YWxpY2U6") {
			t.Fatalf("secret leaked in %s=%s", k, v)
		}
	}
	if len(x.Secret) == 0 {
		t.Fatal("secret fields not marked")
	}
}

func TestNotHTTPAndOversizedHead(t *testing.T) {
	if out := parsertest.Run(New, parsertest.C2S([]byte("\x16\x03\x01\x00\x10garbagegarbage"))); len(out) != 0 {
		t.Fatalf("binary produced %v", out)
	}
	big := "GET / HTTP/1.1\r\n" + strings.Repeat("X-A: "+strings.Repeat("b", 100)+"\r\n", 400)
	if out := parsertest.Run(New, parsertest.C2S([]byte(big))); len(out) != 0 {
		t.Fatalf("oversized head produced %v", out)
	}
}

func TestConnectTunnelStopsParsing(t *testing.T) {
	out := parsertest.Run(New,
		parsertest.C2S([]byte("CONNECT h:443 HTTP/1.1\r\nHost: h:443\r\n\r\n")),
		parsertest.S2C([]byte("HTTP/1.1 200 Connection established\r\n\r\n")),
		parsertest.C2S([]byte("\x16\x03\x01 not http at all")),
		parsertest.S2C([]byte("opaque tunnel bytes")),
	)
	if len(out) != 1 || out[0].Attr["http.method"] != "CONNECT" {
		t.Fatalf("%+v", out)
	}
}

func FuzzHTTP(f *testing.F) {
	parsertest.Fuzz(f, New,
		[]parsertest.Step{parsertest.C2S([]byte(quotientReq)), parsertest.S2C([]byte(okResp))},
		[]parsertest.Step{parsertest.C2S([]byte("POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n")),
			parsertest.S2C([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nz\r\n0\r\n\r\n"))},
	)
}
