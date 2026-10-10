package origin

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRegistrableDomain(t *testing.T) {
	cases := map[string]string{
		"www.example.com":        "example.com",
		"a.b.example.co.uk":      "example.co.uk",
		"example.com":            "example.com",
		"staging.cloudflare.com": "cloudflare.com",
	}
	for in, want := range cases {
		if got := registrableDomain(in); got != want {
			t.Errorf("registrableDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExtractTitle(t *testing.T) {
	if got := extractTitle([]byte("<html><head><TITLE> Hi There </TITLE>")); got != "Hi There" {
		t.Errorf("got %q", got)
	}
	if got := extractTitle([]byte("no title here")); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestAccumulatorDedupAndFronted(t *testing.T) {
	a := newAccumulator()
	a.add("1.2.3.4", "dns:x", "x.example.com")
	a.add("1.2.3.4", "host:y", "y.example.com")
	a.add("9.9.9.9", "crt.sh", "")
	a.add("not-an-ip", "bad")
	cands := a.candidates(map[string]bool{"1.2.3.4": true})
	if len(cands) != 2 {
		t.Fatalf("expected 2 candidates, got %d", len(cands))
	}
	for _, c := range cands {
		if c.IP == "1.2.3.4" {
			if !c.Fronted || len(c.Sources) != 2 || len(c.Hostnames) != 2 {
				t.Errorf("merge/fronted wrong: %+v", c)
			}
		}
	}
}

func TestCrtshParsing(t *testing.T) {
	const body = `[{"name_value":"*.example.com\nwww.example.com"},{"name_value":"api.example.com"},{"name_value":"other.org"}]`
	f := New(Options{HTTPClient: &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
		if !strings.Contains(r.URL.Host, "crt.sh") {
			t.Errorf("unexpected host %s", r.URL.Host)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
	})}})
	hosts, err := f.crtsh(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"example.com": true, "www.example.com": true, "api.example.com": true}
	if len(hosts) != len(want) {
		t.Fatalf("got %v", hosts)
	}
	for _, h := range hosts {
		if !want[h] {
			t.Errorf("unexpected host %q", h)
		}
	}
}
