package fuzz

import (
	"fmt"
	"math/rand/v2"
	"strings"
)

// The transforms below are the standard WAF-evasion encodings (the families
// catalogued in the bypass package and implemented as tamper scripts in tools
// like WhatWaf and sqlmap). Each takes a payload and returns an equivalent that
// a server may still interpret while a signature may miss.

// randomCase flips the case of letters at random.
func randomCase(s string) string {
	b := []rune(s)
	for i, r := range b {
		if rand.IntN(2) == 0 {
			b[i] = toUpper(r)
		} else {
			b[i] = toLower(r)
		}
	}
	return string(b)
}

func toUpper(r rune) rune {
	if r >= 'a' && r <= 'z' {
		return r - 32
	}
	return r
}

func toLower(r rune) rune {
	if r >= 'A' && r <= 'Z' {
		return r + 32
	}
	return r
}

// urlEncode percent-encodes every byte that is not an unreserved character.
func urlEncode(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		if isUnreserved(c) {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func isUnreserved(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~'
}

// htmlEntities encodes significant HTML characters as numeric entities.
func htmlEntities(s string) string {
	repl := map[rune]string{
		'<': "&#60;", '>': "&#62;", '"': "&#34;", '\'': "&#39;",
		'(': "&#40;", ')': "&#41;", '/': "&#47;",
	}
	var b strings.Builder
	for _, r := range s {
		if e, ok := repl[r]; ok {
			b.WriteString(e)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// unicodeEscape expresses ASCII letters as \uXXXX escapes (useful in JS/JSON
// contexts that normalize them back).
func unicodeEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			fmt.Fprintf(&b, "\\u%04x", r)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// sqlComment inserts inline comments between SQL keywords.
func sqlComment(s string) string {
	for _, kw := range []string{"UNION", "SELECT", "OR", "AND", "FROM", "WHERE"} {
		s = replaceFold(s, kw, insertComments(kw))
	}
	return s
}

func insertComments(kw string) string {
	if len(kw) < 2 {
		return kw
	}
	return kw[:1] + "/**/" + kw[1:]
}

// space2Comment replaces spaces with empty SQL comments.
func space2Comment(s string) string { return strings.ReplaceAll(s, " ", "/**/") }

// jsConcat rewrites "alert" with a JS unicode escape for one letter, a common
// way to keep the call working while breaking a literal-keyword signature.
func jsConcat(s string) string {
	return replaceFold(s, "alert", "al\\u0065rt")
}

// replaceFold replaces all case-insensitive occurrences of old with repl.
func replaceFold(s, old, repl string) string {
	if old == "" {
		return s
	}
	var b strings.Builder
	lo := strings.ToLower(s)
	loOld := strings.ToLower(old)
	for {
		i := strings.Index(lo, loOld)
		if i < 0 {
			b.WriteString(s)
			break
		}
		b.WriteString(s[:i])
		b.WriteString(repl)
		s = s[i+len(old):]
		lo = lo[i+len(old):]
	}
	return b.String()
}

const tokenChars = "abcdefghijklmnopqrstuvwxyz0123456789"

func randToken(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = tokenChars[rand.IntN(len(tokenChars))]
	}
	return string(b)
}
