// Package plugins contains the WAF signatures used by wafgo.
//
// Every signature is a Plugin: a vendor name plus a Detect function that
// inspects responses through a Matcher. The bundled signatures are generated
// from the upstream wafw00f project by tools/py2go (files ending in _gen.go);
// hand-written plugins can live next to them and call register from init.
package plugins

import (
	"bytes"
	"fmt"
	"regexp"
	"regexp/syntax"
	"sort"
	"strings"
	"unicode/utf8"
)

// Matcher is the view of the scanned site a Plugin works with. The "attack"
// argument selects the response to the attack request (true) or to the
// normal request (false). When the selected response is missing every method
// reports false.
type Matcher interface {
	// MatchHeader reports whether header name matches p.
	MatchHeader(name string, p *Pattern, attack bool) bool
	// MatchCookie reports whether any Set-Cookie value matches p.
	MatchCookie(p *Pattern, attack bool) bool
	// MatchContent reports whether the response body matches p.
	MatchContent(p *Pattern, attack bool) bool
	// MatchStatus reports whether the status code equals code.
	MatchStatus(code int, attack bool) bool
	// MatchReason reports whether the HTTP reason phrase equals reason.
	MatchReason(reason string, attack bool) bool
	// MatchHeaderBlob matches against the whole raw header block
	// ("Name: value" lines), as nuclei's `part: header` does.
	MatchHeaderBlob(p *Pattern, attack bool) bool
	// MatchResponseBlob matches against the status line, raw headers and
	// body together, as nuclei's `part: response` does.
	MatchResponseBlob(p *Pattern, attack bool) bool
}

// Source identifies where a signature came from.
type Source string

// Signature sources.
const (
	SourceWafw00f Source = "wafw00f" // ported from EnableSecurity/wafw00f
	SourceNuclei  Source = "nuclei"  // from projectdiscovery/nuclei-templates waf-detect
)

// Plugin is a single WAF signature.
type Plugin struct {
	// ID is the short, stable identifier (the upstream module name), e.g. "cloudflare".
	ID string
	// Name is the full display name, e.g. "Cloudflare (Cloudflare Inc.)".
	Name string
	// Source is where the signature came from.
	Source Source
	// Detect reports whether the WAF is present.
	Detect func(m Matcher) bool
}

// Product returns the WAF name without the manufacturer, e.g. "Cloudflare".
func (p Plugin) Product() string {
	product, _ := splitName(p.Name)
	return product
}

// Manufacturer returns the manufacturer, e.g. "Cloudflare Inc.".
func (p Plugin) Manufacturer() string {
	_, manufacturer := splitName(p.Name)
	return manufacturer
}

// SplitName splits "Product (Manufacturer)" into its two parts.
func SplitName(name string) (product, manufacturer string) { return splitName(name) }

func splitName(name string) (string, string) {
	i := strings.Index(name, "(")
	if i < 0 {
		return strings.TrimSpace(name), ""
	}
	return strings.TrimSpace(name[:i]), strings.TrimSpace(strings.ReplaceAll(name[i+1:], ")", ""))
}

var (
	registry = map[string]Plugin{}
	extra    []Plugin // nuclei and other supplementary sources
	core     []Plugin // wafw00f, in priority order; cached
	ordered  []Plugin // core + extra; cached
)

// register adds a wafw00f signature. It is called from init functions only.
func register(id, name string, detect func(Matcher) bool) {
	add(Plugin{ID: id, Name: name, Source: SourceWafw00f, Detect: detect})
}

// registerExtra adds a supplementary signature (e.g. nuclei).
func registerExtra(id, name string, source Source, detect func(Matcher) bool) {
	add(Plugin{ID: id, Name: name, Source: source, Detect: detect})
}

func add(p Plugin) {
	if _, dup := registry[p.ID]; dup {
		panic("plugins: duplicate plugin id " + p.ID)
	}
	registry[p.ID] = p
	if p.Source == SourceWafw00f {
		core = nil
	} else {
		extra = append(extra, p)
	}
	ordered = nil
}

// Core returns only the wafw00f signatures, in the upstream priority order
// followed by any remaining ones sorted by name. This is the set the parity
// tests pin against.
func Core() []Plugin {
	if core != nil {
		return core
	}
	byName := make(map[string]Plugin)
	for _, p := range registry {
		if p.Source == SourceWafw00f {
			byName[p.Name] = p
		}
	}
	out := make([]Plugin, 0, len(byName))
	seen := make(map[string]bool, len(byName))
	for _, name := range priority {
		if p, ok := byName[name]; ok && !seen[name] {
			out = append(out, p)
			seen[name] = true
		}
	}
	var rest []Plugin
	for _, p := range byName {
		if !seen[p.Name] {
			rest = append(rest, p)
		}
	}
	sort.Slice(rest, func(i, j int) bool { return rest[i].Name < rest[j].Name })
	core = append(out, rest...)
	return core
}

// All returns every signature in check order: the wafw00f set first, then the
// supplementary (nuclei) signatures sorted by name.
func All() []Plugin {
	if ordered != nil {
		return ordered
	}
	rest := append([]Plugin(nil), extra...)
	sort.Slice(rest, func(i, j int) bool { return rest[i].Name < rest[j].Name })
	ordered = append(append([]Plugin(nil), Core()...), rest...)
	return ordered
}

// Lookup finds a plugin by ID, full name or product name (case-insensitive).
func Lookup(query string) (Plugin, bool) {
	q := strings.TrimSpace(query)
	if p, ok := registry[strings.ToLower(q)]; ok {
		return p, true
	}
	for _, p := range All() {
		if strings.EqualFold(p.Name, q) || strings.EqualFold(p.Product(), q) {
			return p, true
		}
	}
	return Plugin{}, false
}

// Pattern is a precompiled, case-insensitive signature regex. Patterns that are
// plain ASCII literals skip the regex engine when matching a Text and use a
// substring search over the lower-cased body instead, which is several times
// faster on large bodies and gives exactly the same answer.
type Pattern struct {
	src string
	re  *regexp.Regexp
	lit []byte // lower-cased literal, nil when the regex engine is needed
}

// rx compiles a wafw00f signature. Upstream matches everything with re.I.
func rx(expr string) *Pattern {
	p, err := Compile(expr)
	if err != nil {
		panic(err)
	}
	return p
}

// Compile compiles expr as a case-insensitive Pattern.
func Compile(expr string) (*Pattern, error) {
	re, err := regexp.Compile("(?i)" + expr)
	if err != nil {
		return nil, fmt.Errorf("plugins: bad signature %q: %w", expr, err)
	}
	p := &Pattern{src: expr, re: re}
	if lit, ok := asciiLiteral(expr); ok {
		p.lit = asciiLower([]byte(lit))
	}
	return p, nil
}

// nx compiles a nuclei regex matcher. Unlike rx it does not force
// case-insensitivity: nuclei regex patterns carry their own (?i) when wanted.
func nx(expr string) *Pattern {
	re, err := regexp.Compile(expr)
	if err != nil {
		panic(fmt.Errorf("plugins: bad nuclei regex %q: %w", expr, err))
	}
	return &Pattern{src: expr, re: re}
}

// nw compiles a nuclei word matcher: a case-sensitive literal substring.
func nw(word string) *Pattern {
	return &Pattern{src: word, re: regexp.MustCompile(regexp.QuoteMeta(word))}
}

func asciiLiteral(expr string) (string, bool) {
	t, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return "", false
	}
	t = t.Simplify()
	if t.Op != syntax.OpLiteral || len(t.Rune) == 0 {
		return "", false
	}
	s := string(t.Rune)
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return "", false
		}
	}
	return s, true
}

// String returns the original signature expression.
func (p *Pattern) String() string { return p.src }

// MatchString reports whether s contains a match.
func (p *Pattern) MatchString(s string) bool { return p.re.MatchString(s) }

// Match reports whether t contains a match.
func (p *Pattern) Match(t *Text) bool {
	if p.lit != nil && !t.fold {
		return bytes.Contains(t.lower, p.lit)
	}
	return p.re.Match(t.raw)
}

// Text is a response body prepared once for matching against many patterns.
type Text struct {
	raw   []byte
	lower []byte
	// fold is set when the body contains a non-ASCII rune that (?i) folds
	// onto an ASCII letter (KELVIN SIGN, LATIN SMALL LETTER LONG S). The
	// literal fast path is skipped for such bodies to stay exact.
	fold bool
}

// NewText prepares body for matching.
func NewText(body []byte) *Text {
	return &Text{
		raw:   body,
		lower: asciiLower(body),
		fold:  bytes.Contains(body, []byte("\u212a")) || bytes.Contains(body, []byte("\u017f")),
	}
}

// Bytes returns the raw body.
func (t *Text) Bytes() []byte { return t.raw }

func asciiLower(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}
