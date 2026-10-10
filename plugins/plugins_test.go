package plugins

// Ported from wafw00f tests/test_manager.py, plus registry and pattern checks.

import (
	"math/rand/v2"
	"regexp"
	"strings"
	"testing"
)

func TestAllNotEmpty(t *testing.T) {
	if len(All()) == 0 {
		t.Fatal("no plugins registered")
	}
}

func TestPluginsHaveNameAndDetect(t *testing.T) {
	for _, p := range All() {
		if p.ID == "" || p.Name == "" {
			t.Errorf("plugin %+v missing ID or Name", p)
		}
		if p.Detect == nil {
			t.Errorf("plugin %s has no Detect function", p.ID)
		}
		if p.Product() == "" || p.Manufacturer() == "" {
			t.Errorf("plugin %s name %q is not in \"Product (Manufacturer)\" form", p.ID, p.Name)
		}
	}
}

func TestKnownPluginsLoaded(t *testing.T) {
	for _, id := range []string{"cloudflare", "fastly", "awswaf", "anubis"} {
		if _, ok := registry[id]; !ok {
			t.Errorf("expected plugin %s not found", id)
		}
	}
}

func TestUniqueNames(t *testing.T) {
	seen := map[string]string{}
	for _, p := range All() {
		if other, dup := seen[p.Name]; dup {
			t.Errorf("plugins %s and %s share the name %q", p.ID, other, p.Name)
		}
		seen[p.Name] = p.ID
	}
}

func TestPriorityOrder(t *testing.T) {
	all := All()
	if len(all) != len(registry) {
		t.Fatalf("All() returned %d plugins, registry has %d", len(all), len(registry))
	}
	for i, name := range priority {
		if _, ok := Lookup(name); !ok {
			t.Errorf("priority entry %q has no plugin", name)
			continue
		}
		if i < len(all) && all[i].Name != name {
			t.Errorf("position %d: got %q, want %q", i, all[i].Name, name)
		}
	}
}

func TestLookup(t *testing.T) {
	for _, q := range []string{"cloudflare", "CLOUDFLARE", "Cloudflare (Cloudflare Inc.)", "cloudflare (cloudflare inc.)", " Cloudflare "} {
		p, ok := Lookup(q)
		if !ok || p.ID != "cloudflare" {
			t.Errorf("Lookup(%q) = %v, %v", q, p.ID, ok)
		}
	}
	if _, ok := Lookup("no such waf"); ok {
		t.Error("unknown name should not be found")
	}
}

func TestSplitName(t *testing.T) {
	cases := map[string][2]string{
		"Cloudflare (Cloudflare Inc.)":               {"Cloudflare", "Cloudflare Inc."},
		"CdnNS Application Gateway (CdnNs/WdidcNet)": {"CdnNS Application Gateway", "CdnNs/WdidcNet"},
		"NoManufacturer":                             {"NoManufacturer", ""},
	}
	for in, want := range cases {
		a, b := SplitName(in)
		if a != want[0] || b != want[1] {
			t.Errorf("SplitName(%q) = %q, %q", in, a, b)
		}
	}
}

func TestCompileError(t *testing.T) {
	if _, err := Compile("(unclosed"); err == nil {
		t.Fatal("expected error")
	}
}

// The literal fast path must agree with the regex engine.
func TestPatternFastPathMatchesRegex(t *testing.T) {
	lits := 0
	alphabet := []rune("abcxyzABCXYZ <>/.-_0123456789\nKſkKsSé中")
	rng := rand.New(rand.NewPCG(1, 2))
	for _, expr := range []string{"Access Denied", "sucuri", "KS", "abc", "a.c", "x-y", "<title>", "Zz9"} {
		p, err := Compile(expr)
		if err != nil {
			t.Fatal(err)
		}
		if p.lit != nil {
			lits++
		}
		re := regexp.MustCompile("(?i)" + expr)
		for i := 0; i < 3000; i++ {
			var b strings.Builder
			for j := rng.IntN(40); j > 0; j-- {
				b.WriteRune(alphabet[rng.IntN(len(alphabet))])
			}
			if rng.IntN(3) == 0 {
				b.WriteString(strings.ToUpper(expr))
			}
			body := []byte(b.String())
			if got, want := p.Match(NewText(body)), re.Match(body); got != want {
				t.Fatalf("%q on %q: fast path %v, regex %v", expr, body, got, want)
			}
		}
	}
	if lits == 0 {
		t.Fatal("no pattern used the literal fast path")
	}
}

func TestPatternFoldSpecials(t *testing.T) {
	p, _ := Compile("kill")
	if !p.Match(NewText([]byte("Kill"))) {
		t.Error("KELVIN SIGN should fold to k like (?i) does")
	}
	p, _ = Compile("sucuri")
	if !p.Match(NewText([]byte("ſucuri"))) {
		t.Error("LONG S should fold to s like (?i) does")
	}
}
