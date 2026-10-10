package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeWAF serves a Cloudflare-like Server header and blocks the attack request.
func fakeWAF() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		if strings.Contains(r.URL.RawQuery, "script") || strings.Contains(r.URL.RawQuery, "UNION") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte("<html><title>home</title></html>"))
	}))
}

func runCLI(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(context.Background(), args, strings.NewReader(""), &out, &errb)
	return out.String(), errb.String(), code
}

func TestVersion(t *testing.T) {
	out, _, code := runCLI(t, "--version")
	if code != exitOK || !strings.Contains(out, "wafgo") {
		t.Fatalf("version: code=%d out=%q", code, out)
	}
}

func TestListJSON(t *testing.T) {
	out, _, code := runCLI(t, "-l", "-f", "json")
	if code != exitOK {
		t.Fatalf("code=%d", code)
	}
	var items []map[string]string
	if err := json.Unmarshal([]byte(out), &items); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if len(items) < 170 {
		t.Fatalf("too few WAFs listed: %d", len(items))
	}
}

func TestNoTargetIsUsageError(t *testing.T) {
	if _, _, code := runCLI(t, "-q"); code != exitUsage {
		t.Fatalf("expected usage error, got %d", code)
	}
}

func TestScanDetectsFakeWAF(t *testing.T) {
	srv := fakeWAF()
	defer srv.Close()
	out, _, code := runCLI(t, "-q", srv.URL)
	if code != exitOK {
		t.Fatalf("code=%d out=%q", code, out)
	}
	if !strings.Contains(out, "Cloudflare") {
		t.Fatalf("expected Cloudflare detection, got %q", out)
	}
}

func TestScanJSONOutput(t *testing.T) {
	srv := fakeWAF()
	defer srv.Close()
	out, _, code := runCLI(t, "-q", "-f", "json", srv.URL)
	if code != exitOK {
		t.Fatalf("code=%d", code)
	}
	var recs []map[string]any
	if err := json.Unmarshal([]byte(out), &recs); err != nil {
		t.Fatalf("bad json: %v\n%s", err, out)
	}
	if len(recs) == 0 || recs[0]["firewall"] != "Cloudflare" {
		t.Fatalf("unexpected records: %v", recs)
	}
}

func TestTestFlagSingleWAF(t *testing.T) {
	srv := fakeWAF()
	defer srv.Close()
	out, _, code := runCLI(t, "-q", "-t", "cloudflare", srv.URL)
	if code != exitOK || !strings.Contains(out, "is behind") {
		t.Fatalf("code=%d out=%q", code, out)
	}
	out, _, _ = runCLI(t, "-q", "-t", "akamai", srv.URL)
	if !strings.Contains(out, "not detected") {
		t.Fatalf("expected non-detection, got %q", out)
	}
}

func TestUnknownTestWAF(t *testing.T) {
	if _, _, code := runCLI(t, "-q", "-t", "nope", "http://x.invalid"); code != exitUsage {
		t.Fatalf("expected usage error, got %d", code)
	}
}

// frontedOnly mimics a CDN (Cloudflare header) that does NOT block attacks.
func frontedOnly() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("CF-RAY", "abc123-LAX")
		_, _ = w.Write([]byte("<html><title>home</title></html>"))
	}))
}

func TestEnforcementDistinguishesCDNFromBlockingWAF(t *testing.T) {
	block := fakeWAF()
	defer block.Close()
	out, _, _ := runCLI(t, "-q", block.URL)
	if !strings.Contains(out, "actively filtering") {
		t.Fatalf("blocking WAF should be reported as actively filtering:\n%s", out)
	}

	cdn := frontedOnly()
	defer cdn.Close()
	out, _, _ = runCLI(t, "-q", cdn.URL)
	if !strings.Contains(out, "Cloudflare") {
		t.Fatalf("expected Cloudflare detection:\n%s", out)
	}
	if !strings.Contains(out, "in path only") {
		t.Fatalf("CDN-only site should be reported as in path only, not blocking:\n%s", out)
	}
}

func TestEnforcementInJSON(t *testing.T) {
	cdn := frontedOnly()
	defer cdn.Close()
	out, _, _ := runCLI(t, "-q", "-f", "json", cdn.URL)
	var recs []map[string]any
	if err := json.Unmarshal([]byte(out), &recs); err != nil {
		t.Fatal(err)
	}
	if recs[0]["enforcement"] != "not_observed" {
		t.Fatalf("expected enforcement=not_observed, got %v", recs[0]["enforcement"])
	}
}

func TestBannerContainsIdentity(t *testing.T) {
	b := banner(newColors(false))
	for _, want := range []string{"github.com/miglen/wafgo", "____", `\__,`} {
		if !strings.Contains(b, want) {
			t.Errorf("banner missing %q:\n%s", want, b)
		}
	}
}

func TestConcurrentMultiTargetKeepsOrderAndCount(t *testing.T) {
	// Several fake targets scanned with concurrency > 1 must all appear, in
	// input order, once each.
	var srvs []*httptest.Server
	var urls []string
	for i := 0; i < 6; i++ {
		s := frontedOnly()
		defer s.Close()
		srvs = append(srvs, s)
		urls = append(urls, s.URL)
	}
	args := append([]string{"-q", "-c", "6", "-f", "json"}, urls...)
	out, _, code := runCLI(t, args...)
	if code != exitOK {
		t.Fatalf("code=%d", code)
	}
	var recs []map[string]any
	if err := json.Unmarshal([]byte(out), &recs); err != nil {
		t.Fatal(err)
	}
	if len(recs) != len(urls) {
		t.Fatalf("got %d records, want %d", len(recs), len(urls))
	}
	for i, u := range urls {
		if recs[i]["url"] != u {
			t.Fatalf("record %d out of order: got %v want %s", i, recs[i]["url"], u)
		}
	}
}
