// Package wafgo fingerprints Web Application Firewalls (WAFs).
//
// It is a Go port of wafw00f (https://github.com/EnableSecurity/wafw00f)
// that keeps wafw00f's signatures and detection logic while sending the
// probe requests concurrently over reused connections.
//
// Basic use:
//
//	eng, err := wafgo.New(wafgo.Options{})
//	if err != nil { ... }
//	rep, err := eng.Scan(ctx, "https://example.com")
//	for _, w := range rep.WAFs { fmt.Println(w.Name) }
package wafgo

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miglen/wafgo/plugins"
)

// Version is the wafgo version. It is overridden at build time with
// -ldflags "-X github.com/miglen/wafgo.Version=...".
var Version = "dev"

// UpstreamVersion is the wafw00f release the signatures were generated from.
const UpstreamVersion = "2.4.2"

const (
	// DefaultTimeout is the per-request timeout used when Options.Timeout is zero.
	DefaultTimeout = 7 * time.Second
	// MaxResponseSize is the default cap on how much of a body is read (100 KiB).
	MaxResponseSize = 100 * 1024
	maxRedirects    = 30
)

// Attack payloads, identical to wafw00f.
const (
	XSSPayload  = `<script>alert("XSS");</script>`
	SQLiPayload = `UNION SELECT ALL FROM information_schema AND " or SLEEP(5) or "`
	LFIPayload  = `../../etc/passwd`
	RCEPayload  = `/bin/cat /etc/passwd; ping 127.0.0.1; curl google.com`
	XXEPayload  = `<!ENTITY xxe SYSTEM "file:///etc/shadow">]><pwn>&hack;</pwn>`
)

// DefaultHeaders returns the browser-like header set sent with every request.
func DefaultHeaders() http.Header {
	return http.Header{
		"Accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3"},
		"User-Agent":                {"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:130.0) Gecko/20100101 Firefox/130.0"},
		"Accept-Language":           {"en-US,en;q=0.5"},
		"Upgrade-Insecure-Requests": {"1"},
		"Sec-Fetch-Dest":            {"document"},
		"Sec-Fetch-Mode":            {"navigate"},
		"Sec-Fetch-Site":            {"cross-site"},
		"Priority":                  {"u=0, i"},
		"Dnt":                       {"1"},
	}
}

// Options configures an Engine. The zero value is ready to use.
type Options struct {
	// Timeout per request, including reading the body. Zero means DefaultTimeout.
	Timeout time.Duration
	// NoRedirect disables following 3xx redirects.
	NoRedirect bool
	// Proxy is an http://, https:// or socks5:// proxy URL. When empty the
	// standard HTTP_PROXY / HTTPS_PROXY / NO_PROXY variables are honoured.
	Proxy string
	// Headers replaces the default header set when non-nil (as wafw00f -H does).
	Headers http.Header
	// FindAll keeps checking after the first matching signature and always
	// runs the generic detection.
	FindAll bool
	// MaxBodySize caps how many body bytes are read. Zero means MaxResponseSize.
	MaxBodySize int64
	// Transport overrides the HTTP transport (mainly for tests).
	Transport http.RoundTripper
}

// Engine runs scans. It is safe for concurrent use and reuses connections
// across scans, so create one and share it.
type Engine struct {
	opts    Options
	client  *http.Client
	headers http.Header
}

// New creates an Engine.
func New(opts Options) (*Engine, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.MaxBodySize <= 0 {
		opts.MaxBodySize = MaxResponseSize
	}
	headers := opts.Headers
	if headers == nil {
		headers = DefaultHeaders()
	}

	rt := opts.Transport
	if rt == nil {
		proxy := http.ProxyFromEnvironment
		if opts.Proxy != "" {
			u, err := url.Parse(opts.Proxy)
			if err != nil || u.Scheme == "" || u.Host == "" {
				return nil, fmt.Errorf("wafgo: invalid proxy %q", opts.Proxy)
			}
			proxy = http.ProxyURL(u)
		}
		dialer := &net.Dialer{Timeout: opts.Timeout, KeepAlive: 30 * time.Second}
		rt = &http.Transport{
			Proxy:       proxy,
			DialContext: dialer.DialContext,
			// WAF fingerprinting must work against misconfigured and
			// self-signed sites, exactly like wafw00f (verify=False).
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // intentional, see above
				MinVersion:         tls.VersionTLS10,
			},
			TLSHandshakeTimeout:   opts.Timeout,
			ResponseHeaderTimeout: opts.Timeout,
			MaxIdleConns:          512,
			MaxIdleConnsPerHost:   16,
			IdleConnTimeout:       30 * time.Second,
			// HTTP/1.1 keeps the reason phrase that several signatures match on.
			ForceAttemptHTTP2: false,
		}
	}

	client := &http.Client{
		Transport: rt,
		Timeout:   opts.Timeout,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if opts.NoRedirect {
				return http.ErrUseLastResponse
			}
			if len(via) >= maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			return nil
		},
	}
	return &Engine{opts: opts, client: client, headers: headers}, nil
}

// Options returns the effective options.
func (e *Engine) Options() Options { return e.opts }

// Headers returns a copy of the header set sent with every request.
func (e *Engine) Headers() http.Header { return e.headers.Clone() }

// Response is a captured HTTP response.
type Response struct {
	StatusCode int
	// Reason is the reason phrase from the status line, e.g. "Forbidden".
	Reason string
	Header http.Header
	// Body holds at most Options.MaxBodySize bytes.
	Body []byte
	// URL is the final URL after redirects.
	URL string

	text *plugins.Text
}

// Param is a single query parameter; order is preserved.
type Param struct{ Key, Value string }

// Request describes one probe.
type Request struct {
	// URL is the full URL to fetch. The path is sent as-is, without
	// normalisation, so traversal sequences survive.
	URL string
	// Method is the HTTP method; empty means GET.
	Method string
	// Params are appended to the query string.
	Params []Param
	// Header overrides the engine headers when non-nil.
	Header http.Header
	// Body is the raw request body (for POST/PUT). When set and no
	// Content-Type header is present, application/x-www-form-urlencoded is used.
	Body []byte
}

// Do sends a single request. It returns an error for transport failures;
// HTTP error statuses are not errors.
func (e *Engine) Do(ctx context.Context, r Request) (*Response, error) {
	u, err := url.Parse(r.URL)
	if err != nil {
		return nil, err
	}
	if len(r.Params) > 0 {
		var b strings.Builder
		b.WriteString(u.RawQuery)
		for _, p := range r.Params {
			if b.Len() > 0 {
				b.WriteByte('&')
			}
			b.WriteString(url.QueryEscape(p.Key))
			b.WriteByte('=')
			b.WriteString(url.QueryEscape(p.Value))
		}
		u.RawQuery = b.String()
	}
	method := r.Method
	if method == "" {
		method = http.MethodGet
	}
	var bodyReader io.Reader
	if r.Body != nil {
		bodyReader = strings.NewReader(string(r.Body))
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bodyReader)
	if err != nil {
		return nil, err
	}
	// Keep the exact path (http.NewRequest would otherwise re-parse it).
	req.URL = u
	h := r.Header
	if h == nil {
		h = e.headers
	}
	req.Header = h.Clone()
	if _, ok := req.Header["User-Agent"]; !ok {
		// An empty value stops net/http from adding its own User-Agent.
		req.Header["User-Agent"] = []string{""}
	}
	if r.Body != nil && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if host := req.Header.Get("Host"); host != "" {
		req.Host = host
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read at most MaxBodySize; a body cut short by the timeout is kept, the
	// same way wafw00f keeps the chunks it already read.
	body, err := io.ReadAll(io.LimitReader(resp.Body, e.opts.MaxBodySize))
	if err != nil && len(body) == 0 && !isTimeout(err) {
		return nil, err
	}
	return &Response{
		StatusCode: resp.StatusCode,
		Reason:     reasonPhrase(resp),
		Header:     resp.Header,
		Body:       body,
		URL:        resp.Request.URL.String(),
		text:       plugins.NewText(body),
	}, nil
}

func reasonPhrase(resp *http.Response) string {
	code := strconv.Itoa(resp.StatusCode)
	if r, ok := strings.CutPrefix(resp.Status, code+" "); ok {
		return r
	}
	if resp.Status == code {
		return ""
	}
	return http.StatusText(resp.StatusCode)
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout() || errors.Is(err, context.DeadlineExceeded)
}

// counter counts requests sent during one scan.
type counter struct{ n atomic.Int64 }

func (c *counter) do(ctx context.Context, e *Engine, r Request) *Response {
	resp, err := e.Do(ctx, r)
	if err != nil {
		return nil
	}
	c.n.Add(1)
	return resp
}
