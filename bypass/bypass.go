// Package bypass is a reference catalog of WAF-evasion techniques and of
// publicly documented, WAF-specific bypasses, for use during authorized
// security assessments.
//
// wafgo reports *which* techniques exist and *where* they are documented; it
// does not generate attack traffic. The per-WAF entries cite public research
// (PayloadsAllTheThings, WhatWaf) instead of reproducing payloads, so testers
// can review the primary source and apply it within their engagement scope.
//
// Use only against systems you are authorized to test.
package bypass

import (
	"sort"
	"strings"
)

// Category groups evasion techniques by the mechanism they exploit.
type Category string

// Technique categories, mirroring the families implemented as "tamper"
// scripts in Ekultek/WhatWaf and documented across public WAF research.
const (
	CatEncoding      Category = "encoding"      // represent the payload in an alternate encoding
	CatCase          Category = "case"          // change letter case to defeat case-sensitive rules
	CatComment       Category = "comment"       // inject inline comments to break token matching
	CatWhitespace    Category = "whitespace"    // substitute or insert whitespace/separators
	CatObfuscation   Category = "obfuscation"   // split, concatenate or alias keywords
	CatProtocol      Category = "protocol"      // abuse HTTP parsing differences (verb, headers, params)
	CatNormalization Category = "normalization" // rely on Unicode/charset normalization after the WAF
)

// Technique is a generic, WAF-agnostic evasion technique.
type Technique struct {
	Name        string   `json:"name"`
	Category    Category `json:"category"`
	Description string   `json:"description"`
	References  []string `json:"references,omitempty"`
}

// Techniques returns the generic technique catalog, sorted by category then name.
func Techniques() []Technique {
	out := append([]Technique(nil), techniques...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// Reference is a publicly documented, WAF-specific bypass.
type Reference struct {
	Date    string `json:"date,omitempty"`   // when it was published, if known
	Credit  string `json:"credit,omitempty"` // researcher credited by the source
	Vector  string `json:"vector"`           // the injection context, e.g. "Reflected XSS"
	Summary string `json:"summary"`          // one-line description of the mechanism
	Source  string `json:"source"`           // where it is documented
	URL     string `json:"url"`              // link to the primary source
}

// WAF holds the documented bypasses for one product.
type WAF struct {
	Product    string      `json:"product"`
	References []Reference `json:"references"`
}

// For returns the documented bypasses for a WAF product (matched case- and
// punctuation-insensitively on the product name) and whether any were found.
func For(product string) (WAF, bool) {
	key := normalize(product)
	for _, w := range wafBypasses {
		if normalize(w.Product) == key {
			return w, true
		}
	}
	// Fall back to a prefix match so "Cloudflare (Cloudflare Inc.)" matches "Cloudflare".
	for _, w := range wafBypasses {
		if strings.HasPrefix(key, normalize(w.Product)) || strings.HasPrefix(normalize(w.Product), key) {
			return w, true
		}
	}
	return WAF{}, false
}

// Products lists the WAFs that have documented, product-specific bypasses.
func Products() []string {
	out := make([]string, 0, len(wafBypasses))
	for _, w := range wafBypasses {
		out = append(out, w.Product)
	}
	sort.Strings(out)
	return out
}

func normalize(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

const (
	srcPATT    = "PayloadsAllTheThings"
	urlPATTXSS = "https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/3%20-%20XSS%20Common%20WAF%20Bypass.md"
	srcWhatWaf = "WhatWaf"
	urlWhatWaf = "https://github.com/Ekultek/WhatWaf"
)

// techniques is the generic evasion catalog. Descriptions are deliberately
// conceptual: they name the mechanism a defender should test for, not a
// ready-made payload.
var techniques = []Technique{
	{"Mixed / random case", CatCase,
		"Alternate the case of keywords and tag names to defeat rules that match fixed-case tokens.",
		[]string{urlWhatWaf}},
	{"URL encoding", CatEncoding,
		"Percent-encode characters so the WAF's pattern does not match but the server decodes it.",
		[]string{urlWhatWaf}},
	{"Double URL encoding", CatEncoding,
		"Encode the percent sign itself so a single-decode WAF sees inert text while the app double-decodes.",
		[]string{urlWhatWaf}},
	{"HTML entity encoding", CatEncoding,
		"Express characters as HTML named/numeric entities that the browser renders but rule patterns miss.",
		[]string{urlPATTXSS}},
	{"Unicode / UTF-8 encoding", CatEncoding,
		"Use overlong or alternate Unicode encodings of significant characters.",
		[]string{urlWhatWaf}},
	{"Base64 / data URI", CatEncoding,
		"Move the payload into a base64 data: URI or script source that the rule set does not inspect.",
		[]string{urlWhatWaf}},
	{"Inline comment injection", CatComment,
		"Insert language or SQL comments inside keywords to break contiguous-token matching.",
		[]string{urlWhatWaf}},
	{"Alternate whitespace", CatWhitespace,
		"Replace spaces with tabs, newlines, form feeds or comment blocks that the parser still accepts.",
		[]string{urlWhatWaf}},
	{"Keyword splitting / concatenation", CatObfuscation,
		"Break reserved words across string concatenation or variable aliases so no literal keyword appears.",
		[]string{urlWhatWaf}},
	{"Alternate event handlers / tags", CatObfuscation,
		"Use less common HTML tags or event attributes that a signature list omits.",
		[]string{urlPATTXSS}},
	{"HTTP parameter pollution", CatProtocol,
		"Supply a parameter multiple times so the WAF and the app disagree on which value is effective.",
		[]string{urlWhatWaf}},
	{"Verb / content-type tampering", CatProtocol,
		"Switch HTTP method or body content-type so the request bypasses rules scoped to another shape.",
		[]string{urlWhatWaf}},
	{"Post-WAF normalization", CatNormalization,
		"Rely on charset or Unicode normalization applied by the app after the WAF has inspected the request.",
		[]string{urlPATTXSS}},
}

// wafBypasses cites public, product-specific research. Entries link to the
// primary source rather than reproducing the payloads.
var wafBypasses = []WAF{
	{"Cloudflare", []Reference{
		{Date: "2021-01-25", Credit: "@bohdansec", Vector: "Reflected XSS",
			Summary: "SVG/animate-based vector documented as a Cloudflare bypass.", Source: srcPATT, URL: urlPATTXSS},
		{Date: "2020-04-21", Credit: "@bohdansec", Vector: "Reflected XSS",
			Summary: "Event-handler obfuscation variant.", Source: srcPATT, URL: urlPATTXSS},
		{Date: "2019-03-22", Credit: "@RakeshMane10", Vector: "Reflected XSS",
			Summary: "Tag/attribute obfuscation variant.", Source: srcPATT, URL: urlPATTXSS},
	}},
	{"Incapsula", []Reference{
		{Date: "2019-05-11", Credit: "@daveysec", Vector: "Reflected XSS",
			Summary: "Attribute-break vector documented against Imperva Incapsula.", Source: srcPATT, URL: urlPATTXSS},
		{Date: "2018-03-08", Credit: "@Alra3ees", Vector: "Reflected XSS",
			Summary: "Event-handler vector.", Source: srcPATT, URL: urlPATTXSS},
	}},
	{"Akamai", []Reference{
		{Date: "2018-10-28", Credit: "@s0md3v", Vector: "Reflected XSS",
			Summary: "Obfuscated handler vector documented against Akamai.", Source: srcPATT, URL: urlPATTXSS},
		{Date: "2018-06-18", Credit: "@zseano", Vector: "Reflected XSS",
			Summary: "Attribute-injection vector.", Source: srcPATT, URL: urlPATTXSS},
	}},
	{"Wordfence", []Reference{
		{Date: "2018-09-12", Credit: "@brutelogic", Vector: "Reflected XSS",
			Summary: "Compact handler vector documented against WordFence.", Source: srcPATT, URL: urlPATTXSS},
	}},
	{"Fortiweb", []Reference{
		{Date: "2019-07-09", Credit: "@rezaduty", Vector: "Reflected XSS",
			Summary: "Vector documented against FortiWeb.", Source: srcPATT, URL: urlPATTXSS},
	}},
}
