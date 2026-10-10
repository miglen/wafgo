package wafgo

// Ported from wafw00f tests/test_matching.py.

import (
	"net/http"
	"testing"

	"github.com/miglen/wafgo/plugins"
)

func resp(status int, headers map[string]string, body, reason string) *Response {
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}
	if reason == "" {
		reason = "OK"
	}
	return &Response{StatusCode: status, Reason: reason, Header: h, Body: []byte(body)}
}

func pat(t *testing.T, expr string) *plugins.Pattern {
	t.Helper()
	p, err := plugins.Compile(expr)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestMatchHeader(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string]string
		header  string
		expr    string
		want    bool
	}{
		{"exact", map[string]string{"Server": "cloudflare"}, "Server", "cloudflare", true},
		{"regex", map[string]string{"Server": "cloudflare-nginx"}, "Server", `cloudflare.*`, true},
		{"case insensitive value", map[string]string{"Server": "CLOUDFLARE"}, "Server", "cloudflare", true},
		{"case insensitive name", map[string]string{"Server": "cloudflare"}, "server", "cloudflare", true},
		{"not found", map[string]string{"Server": "nginx"}, "Server", "cloudflare", false},
		{"missing", nil, "Server", "cloudflare", false},
		{"empty value", map[string]string{"Server": ""}, "Server", ".*", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := &Site{Normal: resp(200, c.headers, "", "")}
			if got := s.MatchHeader(c.header, pat(t, c.expr), false); got != c.want {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestMatchHeaderNilResponse(t *testing.T) {
	s := &Site{}
	if s.MatchHeader("Server", pat(t, "cloudflare"), false) {
		t.Fatal("nil response must not match")
	}
}

func TestMatchHeaderAttackSelectsAttackResponse(t *testing.T) {
	s := &Site{
		Normal: resp(200, map[string]string{"Server": "nginx"}, "", ""),
		Attack: resp(403, map[string]string{"Server": "cloudflare"}, "", ""),
	}
	if s.MatchHeader("Server", pat(t, "cloudflare"), false) {
		t.Fatal("normal response should not match")
	}
	if !s.MatchHeader("Server", pat(t, "cloudflare"), true) {
		t.Fatal("attack response should match")
	}
}

func TestMatchHeaderMultipleValuesJoined(t *testing.T) {
	r := resp(200, nil, "", "")
	r.Header.Add("Via", "1.1 varnish")
	r.Header.Add("Via", "1.1 squid")
	s := &Site{Normal: r}
	if !s.MatchHeader("Via", pat(t, `varnish, 1\.1 squid`), false) {
		t.Fatal("multi-valued headers should be joined with ', ' like requests does")
	}
}

func TestMatchContent(t *testing.T) {
	cases := []struct {
		name, body, expr string
		want             bool
	}{
		{"exact", "Access Denied by Cloudflare", "Access Denied", true},
		{"regex", "Error 403: Forbidden by WAF", `Error \d+:.*WAF`, true},
		{"case insensitive", "ACCESS DENIED", "access denied", true},
		{"not found", "Welcome to our website", "Access Denied", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := &Site{Attack: resp(200, nil, c.body, "")}
			if got := s.MatchContent(pat(t, c.expr), true); got != c.want {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestMatchContentNilResponse(t *testing.T) {
	if (&Site{}).MatchContent(pat(t, "test"), true) {
		t.Fatal("nil response must not match")
	}
}

func TestMatchCookie(t *testing.T) {
	cases := []struct {
		name, cookie, expr string
		want               bool
	}{
		{"plain", "__cfduid=abc123; path=/", "__cfduid", true},
		{"regex", "session_id=xyz789; path=/", `session_id=\w+`, true},
		{"not found", "other_cookie=value", "__cfduid", false},
		{"anchored second cookie", "a=1, incap_ses_1=2", `^incap_ses.*?=`, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := &Site{Normal: resp(200, map[string]string{"Set-Cookie": c.cookie}, "", "")}
			if got := s.MatchCookie(pat(t, c.expr), false); got != c.want {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestMatchCookieMultipleSetCookieHeaders(t *testing.T) {
	r := resp(200, nil, "", "")
	r.Header.Add("Set-Cookie", "a=1")
	r.Header.Add("Set-Cookie", "visid_incap_123=abc")
	if !(&Site{Normal: r}).MatchCookie(pat(t, `^visid_incap.*?=`), false) {
		t.Fatal("each Set-Cookie header must be matched individually")
	}
}

func TestMatchStatus(t *testing.T) {
	s := &Site{Attack: resp(200, nil, "", "")}
	if !s.MatchStatus(200, true) {
		t.Error("200 should match")
	}
	if s.MatchStatus(403, true) {
		t.Error("403 should not match")
	}
	s = &Site{Attack: resp(403, nil, "", "")}
	if !s.MatchStatus(403, true) {
		t.Error("403 should match")
	}
	if (&Site{}).MatchStatus(200, true) {
		t.Error("nil response must not match")
	}
}

func TestMatchReason(t *testing.T) {
	s := &Site{Attack: resp(200, nil, "", "OK")}
	if !s.MatchReason("OK", true) {
		t.Error("OK should match")
	}
	if s.MatchReason("Forbidden", true) {
		t.Error("Forbidden should not match")
	}
	s = &Site{Attack: resp(403, nil, "", "Forbidden")}
	if !s.MatchReason("Forbidden", true) {
		t.Error("Forbidden should match")
	}
	if (&Site{}).MatchReason("OK", true) {
		t.Error("nil response must not match")
	}
}
