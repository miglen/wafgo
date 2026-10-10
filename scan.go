package wafgo

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/miglen/wafgo/plugins"
)

// ErrSiteDown is returned by Scan when the normal request fails.
var ErrSiteDown = errors.New("site appears to be down")

// Site holds the responses the signatures are evaluated against. It
// implements plugins.Matcher.
type Site struct {
	// Normal is the response to a plain request (wafw00f's rq).
	Normal *Response
	// Attack is the response to the combined XSS/SQLi/LFI request (wafw00f's attackres).
	Attack *Response
}

var _ plugins.Matcher = (*Site)(nil)

func (s *Site) pick(attack bool) *Response {
	if attack {
		return s.Attack
	}
	return s.Normal
}

// MatchHeader implements plugins.Matcher. Multiple values of a header are
// joined with ", " like Python's requests does.
func (s *Site) MatchHeader(name string, p *plugins.Pattern, attack bool) bool {
	r := s.pick(attack)
	if r == nil {
		return false
	}
	vals := r.Header.Values(name)
	if len(vals) == 0 {
		return false
	}
	val := strings.Join(vals, ", ")
	if val == "" {
		return false
	}
	// wafw00f splits Set-Cookie on ", " to look at each cookie.
	if strings.EqualFold(name, "Set-Cookie") {
		for _, v := range strings.Split(val, ", ") {
			if p.MatchString(v) {
				return true
			}
		}
		return false
	}
	return p.MatchString(val)
}

// MatchCookie implements plugins.Matcher.
func (s *Site) MatchCookie(p *plugins.Pattern, attack bool) bool {
	return s.MatchHeader("Set-Cookie", p, attack)
}

// MatchContent implements plugins.Matcher.
func (s *Site) MatchContent(p *plugins.Pattern, attack bool) bool {
	r := s.pick(attack)
	if r == nil {
		return false
	}
	return p.Match(r.Text())
}

// MatchStatus implements plugins.Matcher.
func (s *Site) MatchStatus(code int, attack bool) bool {
	r := s.pick(attack)
	return r != nil && r.StatusCode == code
}

// MatchReason implements plugins.Matcher.
func (s *Site) MatchReason(reason string, attack bool) bool {
	r := s.pick(attack)
	return r != nil && r.Reason == reason
}

// MatchHeaderBlob implements plugins.Matcher.
func (s *Site) MatchHeaderBlob(p *plugins.Pattern, attack bool) bool {
	r := s.pick(attack)
	return r != nil && p.MatchString(r.headerBlob())
}

// MatchResponseBlob implements plugins.Matcher.
func (s *Site) MatchResponseBlob(p *plugins.Pattern, attack bool) bool {
	r := s.pick(attack)
	if r == nil {
		return false
	}
	if p.MatchString(r.headerBlob()) {
		return true
	}
	return p.Match(r.Text())
}

// headerBlob renders the response headers as sorted "Name: value" lines, so
// nuclei header/response matchers see a stable, full header view.
func (r *Response) headerBlob() string {
	names := make([]string, 0, len(r.Header))
	for name := range r.Header {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP %d %s\r\n", r.StatusCode, r.Reason)
	for _, name := range names {
		for _, v := range r.Header[name] {
			b.WriteString(name)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteString("\r\n")
		}
	}
	return b.String()
}

// Text returns the body prepared for signature matching. Responses returned
// by Engine.Do have it precomputed; for hand-built responses it is computed
// on first use (not safe for concurrent first use).
func (r *Response) Text() *plugins.Text {
	if r.text == nil {
		r.text = plugins.NewText(r.Body)
	}
	return r.text
}

// Identify runs the signatures against site in priority order. Unless findAll
// is set it stops at the first match. When findAll is set, a WAF detected by
// more than one source (e.g. both wafw00f and nuclei) is reported once, by the
// first signature that matched.
func Identify(site *Site, findAll bool) []plugins.Plugin {
	var found []plugins.Plugin
	seen := map[string]bool{}
	for _, p := range plugins.All() {
		if !p.Detect(site) {
			continue
		}
		key := strings.ToLower(p.Product())
		if seen[key] {
			continue
		}
		seen[key] = true
		found = append(found, p)
		if !findAll {
			break
		}
	}
	return found
}

// Generic is the outcome of the generic (behavioural) detection.
type Generic struct {
	// Reason explains why a WAF is suspected.
	Reason string `json:"reason"`
	// Detail gives the observed values.
	Detail string `json:"detail,omitempty"`
	// TriggerURL is the request that triggered the different behaviour, if any.
	TriggerURL string `json:"trigger_url,omitempty"`
}

// Generic detection reasons, as worded by wafw00f.
const (
	ReasonBlocked   = "Blocking is being done at connection/packet level."
	ReasonServer    = "The server header is different when an attack is detected."
	ReasonStatus    = "The server returns a different response code when an attack string is used."
	ReasonUserAgent = "The response was different when the request wasn't made from a browser."
)

// Report is the result of scanning one target.
type Report struct {
	Target string `json:"target"`
	// WAFs are the signatures that matched, in priority order.
	WAFs []plugins.Plugin `json:"-"`
	// TriggerURL is the URL of the attack request the signatures saw.
	TriggerURL string `json:"trigger_url,omitempty"`
	// Generic is set when the generic detection ran and found something.
	Generic *Generic `json:"generic,omitempty"`
	// GenericRan reports whether the generic detection was performed.
	GenericRan bool `json:"-"`
	// Requests is the number of successful HTTP requests made.
	Requests int `json:"requests"`
	// Site gives access to the raw responses.
	Site *Site `json:"-"`
}

// Detected reports whether any WAF (signature or generic) was found.
func (r *Report) Detected() bool { return len(r.WAFs) > 0 || r.Generic != nil }

// probe holds the per-target request plan.
type probe struct {
	e      *Engine
	c      counter
	target string // as given (normal request)
	base   string // scheme://host + path, used for attack requests
	path   string
}

func (e *Engine) newProbe(target string) (*probe, error) {
	u, err := url.Parse(target)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("invalid target URL %q", target)
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	base := u.Scheme + "://" + u.Host
	return &probe{e: e, target: target, base: base, path: path}, nil
}

func (p *probe) attackURL(suffix string) string {
	path := p.path
	if suffix != "" && !strings.HasSuffix(path, "/") {
		path += "/"
	}
	return p.base + path + suffix
}

func (p *probe) normal(ctx context.Context) *Response {
	return p.c.do(ctx, p.e, Request{URL: p.target})
}

func (p *probe) noUserAgent(ctx context.Context) *Response {
	h := p.e.headers.Clone()
	h.Del("User-Agent")
	return p.c.do(ctx, p.e, Request{URL: p.target, Header: h})
}

func (p *probe) withParams(ctx context.Context, payloads ...string) *Response {
	params := make([]Param, len(payloads))
	for i, v := range payloads {
		params[i] = Param{Key: randomParamName(), Value: v}
	}
	return p.c.do(ctx, p.e, Request{URL: p.attackURL(""), Params: params})
}

func (p *probe) central(ctx context.Context) *Response {
	return p.withParams(ctx, XSSPayload, SQLiPayload, LFIPayload)
}

func (p *probe) lfi(ctx context.Context) *Response {
	return p.c.do(ctx, p.e, Request{URL: p.attackURL(LFIPayload)})
}

func randomParamName() string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, 8)
	for i := range b {
		b[i] = letters[rand.IntN(len(letters))]
	}
	return string(b)
}

// parallel runs fns concurrently and returns their results in order.
func parallel(ctx context.Context, fns ...func(context.Context) *Response) []*Response {
	out := make([]*Response, len(fns))
	var wg sync.WaitGroup
	for i, fn := range fns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i] = fn(ctx)
		}()
	}
	wg.Wait()
	return out
}

// Probe sends the normal and the attack request concurrently and returns
// the Site the signatures run against. It returns ErrSiteDown when the
// normal request fails.
func (e *Engine) Probe(ctx context.Context, target string) (*Site, int, error) {
	p, err := e.newProbe(target)
	if err != nil {
		return nil, 0, err
	}
	site := p.site(ctx)
	if site.Normal == nil {
		return nil, int(p.c.n.Load()), ErrSiteDown
	}
	return site, int(p.c.n.Load()), nil
}

func (p *probe) site(ctx context.Context) *Site {
	r := parallel(ctx, p.normal, p.central)
	return &Site{Normal: r[0], Attack: r[1]}
}

// Scan fingerprints target the same way wafw00f does: signatures first, then
// (if nothing matched, or FindAll is set) the generic detection.
func (e *Engine) Scan(ctx context.Context, target string) (*Report, error) {
	return e.scan(ctx, target, nil)
}

// Test checks target for a single WAF signature only.
func (e *Engine) Test(ctx context.Context, target string, plugin plugins.Plugin) (*Report, error) {
	return e.scan(ctx, target, &plugin)
}

func (e *Engine) scan(ctx context.Context, target string, only *plugins.Plugin) (*Report, error) {
	p, err := e.newProbe(target)
	if err != nil {
		return nil, err
	}
	rep := &Report{Target: target}
	site := p.site(ctx)
	rep.Site = site
	if site.Normal == nil {
		rep.Requests = int(p.c.n.Load())
		return rep, ErrSiteDown
	}
	if site.Attack != nil {
		rep.TriggerURL = site.Attack.URL
	}

	if only != nil {
		if only.Detect(site) {
			rep.WAFs = []plugins.Plugin{*only}
		}
		rep.Requests = int(p.c.n.Load())
		return rep, ctx.Err()
	}

	// wafw00f skips signatures entirely when the attack request is blocked.
	if site.Attack != nil {
		rep.WAFs = Identify(site, e.opts.FindAll)
	}
	if e.opts.FindAll || len(rep.WAFs) == 0 {
		rep.GenericRan = true
		rep.Generic = p.generic(ctx, site)
	}
	rep.Requests = int(p.c.n.Load())
	return rep, ctx.Err()
}

// generic mirrors wafw00f's genericdetect. All probes are sent at once and
// then evaluated in wafw00f's order, so the verdict is the same as the
// sequential version while costing a single round-trip.
func (p *probe) generic(ctx context.Context, site *Site) *Generic {
	r := parallel(ctx, p.noUserAgent,
		func(ctx context.Context) *Response { return p.withParams(ctx, XSSPayload) },
		p.lfi,
		func(ctx context.Context) *Response { return p.withParams(ctx, SQLiPayload) },
	)
	normal, noUA, xss, lfi, sqli := site.Normal, r[0], r[1], r[2], r[3]

	if noUA != nil && noUA.StatusCode != normal.StatusCode {
		return &Generic{
			Reason: ReasonUserAgent,
			Detail: fmt.Sprintf(`Normal response code is "%d", while the response code to a modified request is "%d"`,
				normal.StatusCode, noUA.StatusCode),
		}
	}
	attacks := []struct {
		resp *Response
		name string
	}{
		{xss, "cross-site scripting attack"},
		{lfi, "a file inclusion attack"},
		{sqli, "a SQL injection attack"},
	}
	for _, a := range attacks {
		if a.resp == nil {
			return &Generic{Reason: ReasonBlocked}
		}
		if a.resp.StatusCode != normal.StatusCode {
			return &Generic{
				Reason: ReasonStatus,
				Detail: fmt.Sprintf(`Normal response code is "%d", while the response code to %s is "%d"`,
					normal.StatusCode, a.name, a.resp.StatusCode),
				TriggerURL: a.resp.URL,
			}
		}
	}
	normalServer := normal.Header.Get("Server")
	attackServer := ""
	if site.Attack != nil {
		attackServer = site.Attack.Header.Get("Server")
	}
	if normalServer != attackServer {
		return &Generic{
			Reason: ReasonServer,
			Detail: fmt.Sprintf(`The server header for a normal response is "%s", while the server header a response to an attack is "%s"`,
				normalServer, attackServer),
		}
	}
	return nil
}
