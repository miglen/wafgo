// Package origin discovers the real origin server(s) hiding behind a WAF or
// CDN, for authorized reconnaissance. It is the wafgo counterpart of tools
// like cloudbunny: it gathers candidate IP addresses from passive sources
// (DNS, Certificate Transparency logs, and optionally Shodan/Censys) and can
// confirm a candidate by connecting to it directly and comparing the response
// with the fronted site.
//
// Only use this against systems you are authorized to test.
package origin

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

// commonOriginSubdomains are hostnames that frequently resolve to the origin
// directly, bypassing the CDN/WAF in front of the apex and www.
var commonOriginSubdomains = []string{
	"origin", "origin-www", "direct", "direct-connect", "cpanel", "whm",
	"webmail", "mail", "mail2", "smtp", "pop", "imap", "ftp", "sftp", "ssh",
	"dev", "staging", "stage", "test", "uat", "qa", "beta", "demo",
	"admin", "portal", "vpn", "remote", "gateway", "server", "host",
	"www2", "web", "backend", "api-origin", "old", "legacy", "cdn-origin",
}

// Candidate is a possible origin IP address.
type Candidate struct {
	IP        string   `json:"ip"`
	Sources   []string `json:"sources"` // how it was discovered (dns, crt.sh:host, shodan, ...)
	Hostnames []string `json:"hostnames,omitempty"`
	Fronted   bool     `json:"fronted"`   // part of the WAF/CDN-facing set (not an origin)
	Confirmed bool     `json:"confirmed"` // direct connection matched the fronted site
	Note      string   `json:"note,omitempty"`
}

// Result is the outcome of an origin search.
type Result struct {
	Target     string      `json:"target"`
	Domain     string      `json:"domain"`
	Fronted    []string    `json:"fronted_ips"`
	Candidates []Candidate `json:"candidates"`
}

// Options configures a Finder.
type Options struct {
	Timeout      time.Duration // per request/lookup; default 7s
	Active       bool          // confirm candidates by connecting to them directly
	CrtSh        bool          // query crt.sh Certificate Transparency logs (default on)
	Subdomains   bool          // probe common origin subdomains (default on)
	MaxHosts     int           // cap on hostnames resolved from CT logs (default 200)
	ShodanKey    string        // optional Shodan API key
	CensysID     string        // optional Censys API ID
	CensysSecret string        // optional Censys API secret
	Resolver     *net.Resolver // optional custom resolver (tests)
	HTTPClient   *http.Client  // optional custom client (tests)
}

// Finder discovers origin IPs.
type Finder struct {
	opts   Options
	client *http.Client
	res    *net.Resolver
}

// New creates a Finder.
func New(opts Options) *Finder {
	if opts.Timeout <= 0 {
		opts.Timeout = 7 * time.Second
	}
	if opts.MaxHosts <= 0 {
		opts.MaxHosts = 200
	}
	res := opts.Resolver
	if res == nil {
		res = net.DefaultResolver
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: opts.Timeout}
	}
	return &Finder{opts: opts, client: client, res: res}
}

// Find runs every enabled technique and returns the merged candidate list.
func (f *Finder) Find(ctx context.Context, target string) (*Result, error) {
	u, err := url.Parse(target)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("origin: invalid target %q", target)
	}
	host := u.Hostname()
	domain := registrableDomain(host)
	res := &Result{Target: target, Domain: domain}

	acc := newAccumulator()

	// 1. Fronted IPs: what the hostname resolves to right now.
	frontIPs := f.resolve(ctx, host)
	frontSet := map[string]bool{}
	for _, ip := range frontIPs {
		frontSet[ip] = true
		acc.add(ip, "dns:"+host, host)
	}
	res.Fronted = frontIPs

	// 2+. Candidate hostnames from CT logs and common origin subdomains.
	var hosts []string
	if f.opts.CrtSh {
		ctHosts, err := f.crtsh(ctx, domain)
		if err == nil {
			hosts = append(hosts, ctHosts...)
		}
	}
	if f.opts.Subdomains {
		for _, sub := range commonOriginSubdomains {
			hosts = append(hosts, sub+"."+domain)
		}
	}
	f.resolveHosts(ctx, dedupeStrings(hosts), acc)

	// Optional intelligence sources.
	if f.opts.ShodanKey != "" {
		if err := f.shodan(ctx, domain, acc); err != nil {
			acc.note("shodan error: " + err.Error())
		}
	}
	if f.opts.CensysID != "" && f.opts.CensysSecret != "" {
		if err := f.censys(ctx, domain, acc); err != nil {
			acc.note("censys error: " + err.Error())
		}
	}

	candidates := acc.candidates(frontSet)

	// Confirmation: connect directly to each non-fronted candidate.
	if f.opts.Active {
		baseline, ok := f.fingerprint(ctx, "https://"+host, host, "")
		for i := range candidates {
			c := &candidates[i]
			if c.Fronted {
				continue
			}
			fp, ok2 := f.fingerprint(ctx, "https://"+host, host, c.IP)
			switch {
			case ok && ok2 && fp.body == baseline.body:
				c.Confirmed = true
				c.Note = "direct response identical to fronted site"
			case ok2 && fp.status > 0:
				c.Note = fmt.Sprintf("direct connect: HTTP %d, title %q", fp.status, fp.title)
			default:
				c.Note = "no direct HTTP response"
			}
		}
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Confirmed != candidates[j].Confirmed {
			return candidates[i].Confirmed
		}
		if candidates[i].Fronted != candidates[j].Fronted {
			return candidates[j].Fronted
		}
		return candidates[i].IP < candidates[j].IP
	})
	res.Candidates = candidates
	return res, nil
}

func (f *Finder) resolve(ctx context.Context, host string) []string {
	ctx, cancel := context.WithTimeout(ctx, f.opts.Timeout)
	defer cancel()
	addrs, err := f.res.LookupIPAddr(ctx, host)
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range addrs {
		out = append(out, a.IP.String())
	}
	return dedupeStrings(out)
}

func (f *Finder) resolveHosts(ctx context.Context, hosts []string, acc *accumulator) {
	if len(hosts) > f.opts.MaxHosts {
		hosts = hosts[:f.opts.MaxHosts]
	}
	sem := make(chan struct{}, 32)
	var wg sync.WaitGroup
	for _, h := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }()
			for _, ip := range f.resolve(ctx, h) {
				acc.add(ip, "host:"+h, h)
			}
		}(h)
	}
	wg.Wait()
}

type crtshEntry struct {
	NameValue string `json:"name_value"`
}

func (f *Finder) crtsh(ctx context.Context, domain string) ([]string, error) {
	u := "https://crt.sh/?q=%25." + url.QueryEscape(domain) + "&output=json"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	req.Header.Set("User-Agent", "wafgo-origin")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh HTTP %d", resp.StatusCode)
	}
	var entries []crtshEntry
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&entries); err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for _, e := range entries {
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.TrimSpace(strings.TrimPrefix(name, "*."))
			if name != "" && strings.HasSuffix(name, domain) && !strings.ContainsAny(name, " @") {
				set[strings.ToLower(name)] = true
			}
		}
	}
	return mapKeys(set), nil
}

type shodanResp struct {
	Matches []struct {
		IPStr     string   `json:"ip_str"`
		Hostnames []string `json:"hostnames"`
	} `json:"matches"`
}

func (f *Finder) shodan(ctx context.Context, domain string, acc *accumulator) error {
	u := fmt.Sprintf("https://api.shodan.io/shodan/host/search?key=%s&query=%s",
		url.QueryEscape(f.opts.ShodanKey), url.QueryEscape("hostname:"+domain))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	resp, err := f.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var sr shodanResp
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&sr); err != nil {
		return err
	}
	for _, m := range sr.Matches {
		if m.IPStr != "" {
			acc.add(m.IPStr, "shodan", m.Hostnames...)
		}
	}
	return nil
}

type censysResp struct {
	Result struct {
		Hits []struct {
			IP    string   `json:"ip"`
			Names []string `json:"names"`
		} `json:"hits"`
	} `json:"result"`
}

func (f *Finder) censys(ctx context.Context, domain string, acc *accumulator) error {
	u := "https://search.censys.io/api/v2/hosts/search?q=" + url.QueryEscape(domain)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	req.SetBasicAuth(f.opts.CensysID, f.opts.CensysSecret)
	resp, err := f.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var cr censysResp
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&cr); err != nil {
		return err
	}
	for _, h := range cr.Result.Hits {
		if h.IP != "" {
			acc.add(h.IP, "censys", h.Names...)
		}
	}
	return nil
}

type fingerprint struct {
	status int
	title  string
	body   [32]byte
}

// fingerprint fetches rawURL. When ip is set, the TCP connection is forced to
// that IP while TLS SNI and the Host header keep the original hostname, so the
// request reaches a specific server directly.
func (f *Finder) fingerprint(ctx context.Context, rawURL, host, ip string) (fingerprint, bool) {
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, ServerName: host}, //nolint:gosec
		DisableKeepAlives: true,
	}
	if ip != "" {
		dialer := &net.Dialer{Timeout: f.opts.Timeout}
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, _ := net.SplitHostPort(addr)
			if port == "" {
				port = "443"
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
		}
	}
	client := &http.Client{Timeout: f.opts.Timeout, Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ctx, cancel := context.WithTimeout(ctx, f.opts.Timeout)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	req.Host = host
	resp, err := client.Do(req)
	if err != nil {
		return fingerprint{}, false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	return fingerprint{status: resp.StatusCode, title: extractTitle(body), body: sha256.Sum256(body)}, true
}

func extractTitle(body []byte) string {
	s := string(body)
	i := strings.Index(strings.ToLower(s), "<title>")
	if i < 0 {
		return ""
	}
	s = s[i+len("<title>"):]
	j := strings.Index(strings.ToLower(s), "</title>")
	if j < 0 {
		return ""
	}
	return strings.TrimSpace(s[:j])
}

func registrableDomain(host string) string {
	if d, err := publicsuffix.EffectiveTLDPlusOne(strings.TrimSuffix(host, ".")); err == nil {
		return d
	}
	return host
}

// accumulator merges IP findings from several sources.
type accumulator struct {
	mu    sync.Mutex
	ips   map[string]*Candidate
	notes []string
}

func newAccumulator() *accumulator { return &accumulator{ips: map[string]*Candidate{}} }

func (a *accumulator) add(ip, source string, hostnames ...string) {
	if net.ParseIP(ip) == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	c := a.ips[ip]
	if c == nil {
		c = &Candidate{IP: ip}
		a.ips[ip] = c
	}
	c.Sources = addUnique(c.Sources, source)
	for _, h := range hostnames {
		if h != "" {
			c.Hostnames = addUnique(c.Hostnames, strings.ToLower(h))
		}
	}
}

func (a *accumulator) note(s string) {
	a.mu.Lock()
	a.notes = append(a.notes, s)
	a.mu.Unlock()
}

func (a *accumulator) candidates(frontSet map[string]bool) []Candidate {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]Candidate, 0, len(a.ips))
	for ip, c := range a.ips {
		c.Fronted = frontSet[ip]
		sort.Strings(c.Sources)
		sort.Strings(c.Hostnames)
		out = append(out, *c)
	}
	return out
}

func addUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func mapKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
