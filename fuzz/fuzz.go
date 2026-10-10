// Package fuzz actively tests whether a WAF can be bypassed, for authorized
// security assessments. It sends an attack payload and many tampered variants
// of it at a chosen injection point and reports which variants the WAF lets
// through — the same workflow a tester performs by hand, automated.
//
// This package generates traffic. Use it only against systems you are
// authorized to test, and within your engagement's scope.
package fuzz

import (
	"context"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/miglen/wafgo"
)

// Location is where a payload is injected into the request.
type Location string

// Injection locations.
const (
	LocQuery  Location = "query"  // a query-string parameter
	LocPath   Location = "path"   // appended to the URL path
	LocBody   Location = "body"   // a urlencoded POST body parameter
	LocHeader Location = "header" // a request header value
)

// Payload is a seed attack string in a given category.
type Payload struct {
	Category string
	Raw      string
}

// Seeds are canonical, well-known attack strings per category. They mirror the
// vectors wafgo already uses for detection; the point is not the payloads
// themselves but which encodings of them slip past the WAF.
var Seeds = []Payload{
	{"xss", `<script>alert(1)</script>`},
	{"xss", `<img src=x onerror=alert(1)>`},
	{"sqli", `' OR '1'='1`},
	{"sqli", `1 UNION SELECT NULL,NULL--`},
	{"lfi", `../../../../etc/passwd`},
	{"rce", `;cat /etc/passwd`},
	{"traversal", `....//....//etc/passwd`},
}

// Tamper is a named payload transformation (a "tamper" in WhatWaf/sqlmap terms).
type Tamper struct {
	Name  string
	Apply func(string) string
}

// Tampers returns the transformation catalog. "none" (identity) is first so the
// raw payload is always tested as the baseline attack.
func Tampers() []Tamper {
	return []Tamper{
		{"none", func(s string) string { return s }},
		{"case", randomCase},
		{"url", urlEncode},
		{"double-url", func(s string) string { return urlEncode(urlEncode(s)) }},
		{"html-entity", htmlEntities},
		{"unicode", unicodeEscape},
		{"comment", sqlComment},
		{"space2comment", space2Comment},
		{"space2tab", func(s string) string { return strings.ReplaceAll(s, " ", "\t") }},
		{"nullbyte", func(s string) string { return s + "%00" }},
		{"concat", jsConcat},
	}
}

// Options configures a Fuzzer.
type Options struct {
	Location    Location      // default LocQuery
	Param       string        // param/header name; default a generated one
	Categories  []string      // limit to these categories; empty = all
	Tampers     []string      // limit to these tampers by name; empty = all
	Concurrency int           // in-flight requests; default 5
	Delay       time.Duration // pause between requests per worker
}

// Case is the result of sending one payload variant.
type Case struct {
	Category string `json:"category"`
	Seed     string `json:"seed"`
	Tamper   string `json:"tamper"`
	Value    string `json:"value"`
	Status   int    `json:"status"`
	Blocked  bool   `json:"blocked"`
	Bypass   bool   `json:"bypass"` // variant passed although the raw payload was blocked
	Err      string `json:"error,omitempty"`
}

// Result is the full fuzzing outcome for a target.
type Result struct {
	Target        string   `json:"target"`
	Location      Location `json:"location"`
	Param         string   `json:"param"`
	ControlStatus int      `json:"control_status"`
	Cases         []Case   `json:"cases"`
	Requests      int      `json:"requests"`
}

// Bypasses returns only the cases that bypassed the WAF.
func (r *Result) Bypasses() []Case {
	var out []Case
	for _, c := range r.Cases {
		if c.Bypass {
			out = append(out, c)
		}
	}
	return out
}

// Fuzzer drives the engine.
type Fuzzer struct {
	eng  *wafgo.Engine
	opts Options
}

// New creates a Fuzzer using eng for transport (proxy, headers, timeout).
func New(eng *wafgo.Engine, opts Options) *Fuzzer {
	if opts.Location == "" {
		opts.Location = LocQuery
	}
	if opts.Param == "" {
		opts.Param = "q" + randToken(6)
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 5
	}
	return &Fuzzer{eng: eng, opts: opts}
}

var blockMarkers = regexp.MustCompile(`(?i)access denied|request (blocked|rejected|denied)|forbidden|not acceptable|blocked by|security (policy|violation)|web application firewall|attack detected|malicious`)

var hardBlock = map[int]bool{403: true, 406: true, 429: true, 494: true, 501: true}

// Run sends the control request, then every selected payload variant.
func (f *Fuzzer) Run(ctx context.Context, target string) (*Result, error) {
	res := &Result{Target: target, Location: f.opts.Location, Param: f.opts.Param}

	// Control: a benign value in the same injection point tells us what an
	// allowed response looks like.
	control, err := f.send(ctx, target, "wafgo"+randToken(4))
	if err != nil {
		return nil, err
	}
	res.ControlStatus = control.StatusCode
	res.Requests++

	type job struct {
		p Payload
		t Tamper
	}
	var jobs []job
	for _, p := range Seeds {
		if !selected(f.opts.Categories, p.Category) {
			continue
		}
		for _, t := range Tampers() {
			if t.Name != "none" && !selected(f.opts.Tampers, t.Name) {
				continue
			}
			jobs = append(jobs, job{p, t})
		}
	}

	cases := make([]Case, len(jobs))
	var (
		wg sync.WaitGroup
		mu sync.Mutex
	)
	ch := make(chan int)
	for range f.opts.Concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range ch {
				j := jobs[i]
				value := j.t.Apply(j.p.Raw)
				c := Case{Category: j.p.Category, Seed: j.p.Raw, Tamper: j.t.Name, Value: value}
				resp, err := f.send(ctx, target, value)
				if err != nil {
					c.Err = err.Error()
				} else {
					c.Status = resp.StatusCode
					c.Blocked = isBlocked(resp, control)
				}
				mu.Lock()
				cases[i] = c
				res.Requests++
				mu.Unlock()
				if f.opts.Delay > 0 {
					select {
					case <-time.After(f.opts.Delay):
					case <-ctx.Done():
					}
				}
			}
		}()
	}
	for i := range jobs {
		select {
		case ch <- i:
		case <-ctx.Done():
		}
	}
	close(ch)
	wg.Wait()

	// A tamper is a bypass only if the raw payload (tamper "none") for the same
	// seed was itself blocked.
	rawBlocked := map[string]bool{}
	for _, c := range cases {
		if c.Tamper == "none" {
			rawBlocked[c.Seed] = c.Blocked
		}
	}
	for i := range cases {
		c := &cases[i]
		if c.Tamper != "none" && c.Err == "" && !c.Blocked && rawBlocked[c.Seed] {
			c.Bypass = true
		}
	}
	res.Cases = cases
	return res, ctx.Err()
}

func (f *Fuzzer) send(ctx context.Context, target, value string) (*wafgo.Response, error) {
	r := wafgo.Request{URL: target}
	switch f.opts.Location {
	case LocPath:
		r.URL = strings.TrimRight(target, "/") + "/" + value
	case LocBody:
		r.Method = "POST"
		r.Body = []byte(f.opts.Param + "=" + value)
	case LocHeader:
		h := f.eng.Headers()
		h.Set(f.opts.Param, value)
		r.Header = h
	default: // LocQuery
		r.Params = []wafgo.Param{{Key: f.opts.Param, Value: value}}
	}
	return f.eng.Do(ctx, r)
}

func isBlocked(resp, control *wafgo.Response) bool {
	if resp == nil {
		return true
	}
	if hardBlock[resp.StatusCode] {
		return true
	}
	if control != nil && resp.StatusCode != control.StatusCode {
		return true
	}
	return blockMarkers.Match(resp.Body)
}

func selected(list []string, v string) bool {
	if len(list) == 0 {
		return true
	}
	for _, x := range list {
		if strings.EqualFold(strings.TrimSpace(x), v) {
			return true
		}
	}
	return false
}
