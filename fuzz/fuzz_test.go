package fuzz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/miglen/wafgo"
)

// blockingWAF returns 403 when a raw "<script" or "union select" appears in the
// query, but lets percent-encoded or commented variants through with 200.
func blockingWAF() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A realistic WAF inspects the decoded parameter value.
		low := strings.ToLower(r.URL.Query().Get("x"))
		if strings.Contains(low, "<script") || strings.Contains(low, "union select") || strings.Contains(low, "onerror=") {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("Access Denied by WAF"))
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
}

func engineFor(t *testing.T) *wafgo.Engine {
	t.Helper()
	e, err := wafgo.New(wafgo.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestFuzzFindsEncodingBypass(t *testing.T) {
	srv := blockingWAF()
	defer srv.Close()
	f := New(engineFor(t), Options{Location: LocQuery, Param: "x", Concurrency: 4})
	res, err := f.Run(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if res.ControlStatus != 200 {
		t.Fatalf("control status = %d", res.ControlStatus)
	}
	bypasses := res.Bypasses()
	if len(bypasses) == 0 {
		t.Fatal("expected at least one bypass (e.g. url-encoded <script>)")
	}
	// The raw xss payload must have been blocked for a bypass to be reported.
	for _, b := range bypasses {
		if b.Tamper == "none" {
			t.Error("tamper 'none' must never be a bypass")
		}
		if b.Blocked {
			t.Error("a bypass must not be blocked")
		}
	}
	// url tamper on an xss seed should pass.
	var sawURL bool
	for _, b := range bypasses {
		if b.Category == "xss" && (b.Tamper == "url" || b.Tamper == "double-url" || b.Tamper == "html-entity") {
			sawURL = true
		}
	}
	if !sawURL {
		t.Errorf("expected an encoding-based xss bypass, got %+v", bypasses)
	}
}

func TestFuzzCategoryFilter(t *testing.T) {
	srv := blockingWAF()
	defer srv.Close()
	f := New(engineFor(t), Options{Param: "x", Categories: []string{"sqli"}})
	res, err := f.Run(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range res.Cases {
		if c.Category != "sqli" {
			t.Fatalf("category filter leaked %q", c.Category)
		}
	}
}

func TestTampersChangePayload(t *testing.T) {
	// A compound payload that every tamper can act on (tags, spaces, alert,
	// SQL keywords).
	const in = "<script>alert(1)</script> UNION SELECT a OR b"
	for _, tp := range Tampers() {
		if tp.Name == "none" {
			continue
		}
		if tp.Apply(in) == in {
			t.Errorf("tamper %q did not change the payload", tp.Name)
		}
	}
}

func TestURLEncodeRoundytrip(t *testing.T) {
	if got := urlEncode("<a b>"); got != "%3Ca%20b%3E" {
		t.Fatalf("got %q", got)
	}
}
