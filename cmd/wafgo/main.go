// Command wafgo fingerprints Web Application Firewalls.
//
//	wafgo https://example.com
//	wafgo -a -f json -i targets.txt
//
// Run "wafgo -h" for all options.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	flag "github.com/spf13/pflag"

	"github.com/miglen/wafgo"
	"github.com/miglen/wafgo/bypass"
	"github.com/miglen/wafgo/fuzz"
	"github.com/miglen/wafgo/origin"
	"github.com/miglen/wafgo/plugins"
)

const (
	exitOK    = 0
	exitError = 1 // a target could not be scanned or a file could not be used
	exitUsage = 2
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

type config struct {
	verbose     int
	findAll     bool
	noRedirect  bool
	test        string
	output      string
	format      string
	input       string
	list        bool
	proxy       string
	version     bool
	headers     string
	timeout     float64
	noColors    bool
	quiet       bool
	concurrency int

	// Reconnaissance extras.
	origins      bool
	originsAct   bool
	shodanKey    string
	censysID     string
	censysSecret string
	bypass       bool

	// Active bypass fuzzer.
	fuzz        bool
	fuzzParam   string
	fuzzWhere   string
	fuzzCats    string
	fuzzTampers string
	fuzzDelay   float64
	fuzzWorkers int
	fuzzAuthOK  bool
}

func newFlags(cfg *config, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("wafgo", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.SortFlags = false
	fs.CountVarP(&cfg.verbose, "verbose", "v", "increase log verbosity (-v, -vv, -vvv)")
	fs.BoolVarP(&cfg.findAll, "findall", "a", false, "report every matching WAF instead of stopping at the first one")
	fs.BoolVarP(&cfg.noRedirect, "noredirect", "r", false, "do not follow 3xx redirects")
	fs.StringVarP(&cfg.test, "test", "t", "", `test for one WAF only, by id or name (e.g. cloudflare or "AireeCDN (Airee)")`)
	fs.StringVarP(&cfg.output, "output", "o", "", "write results to `file` (format from extension); - for stdout")
	fs.StringVarP(&cfg.format, "format", "f", "", "results format: json, csv or text (without -o results go to stdout)")
	fs.StringVarP(&cfg.input, "input-file", "i", "", "read targets from `file` (.json, .csv with a url column, or one per line); - for stdin")
	fs.BoolVarP(&cfg.list, "list", "l", false, "list all WAFs wafgo can detect")
	fs.StringVarP(&cfg.proxy, "proxy", "p", "", "proxy `url`, e.g. http://host:8080 or socks5://host:1080")
	fs.StringVarP(&cfg.headers, "headers", "H", "", "replace the default headers with \"Name: value\" lines from `file`")
	fs.Float64VarP(&cfg.timeout, "timeout", "T", 7, "per-request timeout in `seconds`")
	fs.IntVarP(&cfg.concurrency, "concurrency", "c", 10, "number of targets scanned in parallel")
	fs.BoolVar(&cfg.noColors, "no-colors", false, "disable ANSI colors (also NO_COLOR env)")
	fs.BoolVarP(&cfg.quiet, "quiet", "q", false, "do not print the banner")
	fs.BoolVarP(&cfg.version, "version", "V", false, "print version and exit")
	fs.BoolVarP(&cfg.origins, "origins", "O", false, "discover candidate origin IPs behind the WAF/CDN (DNS + crt.sh)")
	fs.BoolVar(&cfg.originsAct, "origins-active", false, "with -O, confirm candidates by connecting to them directly")
	fs.StringVar(&cfg.shodanKey, "shodan-key", "", "Shodan API key for origin discovery (or SHODAN_API_KEY)")
	fs.StringVar(&cfg.censysID, "censys-id", "", "Censys API ID for origin discovery (or CENSYS_API_ID)")
	fs.StringVar(&cfg.censysSecret, "censys-secret", "", "Censys API secret (or CENSYS_API_SECRET)")
	fs.BoolVarP(&cfg.bypass, "bypass", "X", false, "show documented bypass techniques for detected WAFs (authorized testing only)")
	fs.BoolVar(&cfg.fuzz, "fuzz", false, "actively send tampered payloads and report which bypass the WAF (requires --authorized-test)")
	fs.BoolVar(&cfg.fuzzAuthOK, "authorized-test", false, "confirm you are authorized to send attack traffic to the target(s)")
	fs.StringVar(&cfg.fuzzWhere, "fuzz-where", "query", "injection point: query, path, body or header")
	fs.StringVar(&cfg.fuzzParam, "fuzz-param", "", "parameter/header name to inject into (default: generated)")
	fs.StringVar(&cfg.fuzzCats, "fuzz-categories", "", "comma-separated payload categories (default: all; e.g. xss,sqli)")
	fs.StringVar(&cfg.fuzzTampers, "fuzz-tampers", "", "comma-separated tampers to try (default: all)")
	fs.Float64Var(&cfg.fuzzDelay, "fuzz-delay", 0, "delay between fuzz requests per worker, in seconds")
	fs.IntVar(&cfg.fuzzWorkers, "fuzz-workers", 5, "concurrent fuzz requests per target")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: wafgo [options] url [url ...]\n\nExamples:\n"+
			"  wafgo https://example.com\n"+
			"  wafgo -a example.com example.org\n"+
			"  wafgo -f json -i targets.txt > results.json\n\nOptions:\n")
		fs.PrintDefaults()
	}
	return fs
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) (code int) {
	terminal := isTerminal(stdout)
	outErrors := &checkedWriter{w: stdout}
	errErrors := &checkedWriter{w: stderr}
	stdout, stderr = outErrors, errErrors
	defer func() {
		if err := errors.Join(outErrors.Err(), errErrors.Err()); err != nil && code == exitOK {
			fmt.Fprintf(stderr, "wafgo: writing output: %v\n", err)
			code = exitError
		}
	}()

	var cfg config
	fs := newFlags(&cfg, stderr)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	usageErr := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "wafgo: "+format+"\n", a...)
		fmt.Fprintln(stderr, "Run 'wafgo -h' for usage.")
		return exitUsage
	}

	level := slog.LevelError
	switch {
	case cfg.verbose >= 3:
		level = slog.LevelDebug
	case cfg.verbose == 2:
		level = slog.LevelInfo
	case cfg.verbose == 1:
		level = slog.LevelWarn
	}
	log := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: level}))

	// Where do machine-readable results go, and is the human log shown?
	var format wafgo.Format
	if cfg.format != "" {
		f, err := wafgo.ParseFormat(cfg.format)
		if err != nil {
			return usageErr("%v", err)
		}
		format = f
	}
	resultsToStdout := cfg.output == "-" || (cfg.output == "" && cfg.format != "")
	if cfg.output != "" && cfg.output != "-" && format == "" {
		format = wafgo.FormatFromPath(cfg.output)
	}
	if format == "" {
		format = wafgo.FormatText
	}
	human := stdout
	if resultsToStdout {
		human = io.Discard
	}
	col := newColors(!cfg.noColors && os.Getenv("NO_COLOR") == "" && terminal)

	if cfg.version {
		fmt.Fprintf(stdout, "wafgo %s (signatures from wafw00f %s)\nLicensed under the BSD 3-Clause license.\n",
			wafgo.Version, wafgo.UpstreamVersion)
		return exitOK
	}
	if cfg.list {
		return listWAFs(stdout, cfg.format, col)
	}

	if !cfg.quiet {
		fmt.Fprint(human, banner(col))
	}

	var targets []string
	if cfg.input != "" {
		r, name := stdin, "stdin.txt"
		if cfg.input != "-" {
			f, err := os.Open(cfg.input)
			if err != nil {
				fmt.Fprintf(stderr, "wafgo: %v\n", err)
				return exitError
			}
			defer f.Close()
			r, name = f, cfg.input
		}
		t, err := wafgo.ReadTargets(r, name)
		if err != nil {
			fmt.Fprintf(stderr, "wafgo: %v\n", err)
			return exitError
		}
		log.Info("loaded targets", "file", cfg.input, "count", len(t))
		targets = append(targets, t...)
	}
	targets = append(targets, fs.Args()...)
	if len(targets) == 0 {
		return usageErr("no test target specified")
	}

	var only *plugins.Plugin
	if cfg.test != "" {
		p, ok := plugins.Lookup(cfg.test)
		if !ok {
			return usageErr("WAF %q was not found in our list; use --list to see what is available", cfg.test)
		}
		only = &p
	}

	opts := wafgo.Options{
		Timeout:    time.Duration(cfg.timeout * float64(time.Second)),
		NoRedirect: cfg.noRedirect,
		Proxy:      cfg.proxy,
		FindAll:    cfg.findAll,
	}
	if cfg.headers != "" {
		h, err := wafgo.ReadHeadersFile(cfg.headers)
		if err != nil {
			fmt.Fprintf(stderr, "wafgo: headers file: %v\n", err)
			return exitError
		}
		if len(h) == 0 {
			return usageErr("please provide a headers file with colon delimited header names and values")
		}
		opts.Headers = h
	}
	eng, err := wafgo.New(opts)
	if err != nil {
		return usageErr("%v", err)
	}

	// Reconnaissance extras are advisory and always visible: when the
	// machine-readable results go to stdout, print them to stderr.
	aux := stdout
	if resultsToStdout {
		aux = stderr
	}
	var finder *origin.Finder
	if cfg.origins {
		finder = origin.New(origin.Options{
			Timeout:      opts.Timeout,
			Active:       cfg.originsAct,
			CrtSh:        true,
			Subdomains:   true,
			ShodanKey:    firstNonEmpty(cfg.shodanKey, os.Getenv("SHODAN_API_KEY")),
			CensysID:     firstNonEmpty(cfg.censysID, os.Getenv("CENSYS_API_ID")),
			CensysSecret: firstNonEmpty(cfg.censysSecret, os.Getenv("CENSYS_API_SECRET")),
		})
	}

	var fuzzer *fuzz.Fuzzer
	if cfg.fuzz {
		if !cfg.fuzzAuthOK {
			return usageErr("--fuzz sends attack traffic; pass --authorized-test to confirm you are authorized to test the target(s)")
		}
		loc := fuzz.Location(strings.ToLower(cfg.fuzzWhere))
		switch loc {
		case fuzz.LocQuery, fuzz.LocPath, fuzz.LocBody, fuzz.LocHeader:
		default:
			return usageErr("invalid --fuzz-where %q (want query, path, body or header)", cfg.fuzzWhere)
		}
		fuzzer = fuzz.New(eng, fuzz.Options{
			Location:    loc,
			Param:       cfg.fuzzParam,
			Categories:  splitList(cfg.fuzzCats),
			Tampers:     splitList(cfg.fuzzTampers),
			Concurrency: cfg.fuzzWorkers,
			Delay:       time.Duration(cfg.fuzzDelay * float64(time.Second)),
		})
	}

	ex := extras{finder: finder, bypass: cfg.bypass, fuzzer: fuzzer, aux: aux, col: col}
	records, failed := scanAll(ctx, eng, targets, only, max(cfg.concurrency, 1), human, col, log, ex)

	if cfg.output != "" || resultsToStdout {
		var err error
		if resultsToStdout {
			err = wafgo.WriteRecords(stdout, format, records)
		} else {
			err = writeFileAtomic(cfg.output, func(w io.Writer) error {
				return wafgo.WriteRecords(w, format, records)
			})
		}
		if err != nil {
			fmt.Fprintf(stderr, "wafgo: writing results: %v\n", err)
			return exitError
		}
	}
	if failed > 0 || ctx.Err() != nil {
		return exitError
	}
	return exitOK
}

// extras carries the opt-in reconnaissance features.
type extras struct {
	finder *origin.Finder // non-nil when origin discovery is enabled
	bypass bool           // print documented bypass techniques
	fuzzer *fuzz.Fuzzer   // non-nil when the active bypass fuzzer is enabled
	aux    io.Writer      // where extras output goes (stdout, or stderr if results use stdout)
	col    colors
}

// scanAll scans targets with a worker pool. Each target's output block is
// printed atomically as soon as it finishes; records keep input order.
func scanAll(ctx context.Context, eng *wafgo.Engine, targets []string, only *plugins.Plugin,
	workers int, human io.Writer, c colors, log *slog.Logger, ex extras) ([]wafgo.Record, int) {

	results := make([][]wafgo.Record, len(targets))
	var (
		mu     sync.Mutex
		failed int
		wg     sync.WaitGroup
	)
	jobs := make(chan int)
	for range min(workers, len(targets)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				var buf, auxBuf bytes.Buffer
				recs, ok := scanOne(ctx, eng, targets[i], only, &buf, c, log, ex, &auxBuf)
				results[i] = recs
				mu.Lock()
				if !ok {
					failed++
				}
				_, _ = human.Write(buf.Bytes())
				if ex.aux == human {
					_, _ = human.Write(auxBuf.Bytes())
				} else {
					_, _ = ex.aux.Write(auxBuf.Bytes())
				}
				mu.Unlock()
			}
		}()
	}
feed:
	for i := range targets {
		select {
		case jobs <- i:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()

	var all []wafgo.Record
	for _, r := range results {
		all = append(all, r...)
	}
	return all, failed
}

func scanOne(ctx context.Context, eng *wafgo.Engine, raw string, only *plugins.Plugin,
	w io.Writer, c colors, log *slog.Logger, ex extras, aux io.Writer) ([]wafgo.Record, bool) {

	target := wafgo.NormalizeTarget(raw)
	if target != raw {
		log.Info("target has no scheme, assuming https", "target", raw)
	}
	fmt.Fprintf(w, "[*] Checking %s\n", target)

	start := time.Now()
	var (
		rep *wafgo.Report
		err error
	)
	if only != nil {
		rep, err = eng.Test(ctx, target, *only)
	} else {
		rep, err = eng.Scan(ctx, target)
	}
	if err != nil {
		log.Error("could not scan target", "target", target, "error", err)
		return nil, false
	}

	if only != nil {
		if len(rep.WAFs) > 0 {
			fmt.Fprintf(w, "[+] The site %s%s%s is behind %s%s%s WAF.\n", c.B, target, c.E, c.C, only.Name, c.E)
		} else {
			fmt.Fprintf(w, "[-] WAF %s was not detected on %s\n", only.Name, target)
		}
	} else {
		if len(rep.WAFs) > 0 {
			names := make([]string, len(rep.WAFs))
			for i, p := range rep.WAFs {
				names[i] = c.C + p.Name + c.E
			}
			fmt.Fprintf(w, "[+] The site %s%s%s is behind %s WAF.\n", c.B, target, c.E, strings.Join(names, " and/or "))
			switch rep.Enforcement {
			case wafgo.EnforcementBlocking:
				fmt.Fprintf(w, "    %s↳ actively filtering%s — %s\n", c.G, c.E, rep.EnforcementReason)
			case wafgo.EnforcementNotObserved:
				fmt.Fprintf(w, "    %s↳ in path only (no blocking observed)%s — likely CDN/proxy; %s\n", c.Y, c.E, rep.EnforcementReason)
			}
		}
		if rep.GenericRan {
			fmt.Fprintln(w, "[+] Generic Detection results:")
			if g := rep.Generic; g != nil {
				fmt.Fprintf(w, "[*] The site %s seems to be behind a WAF or some sort of security solution\n", target)
				fmt.Fprintf(w, "[~] Reason: %s\n", g.Reason)
				if g.Detail != "" {
					fmt.Fprintf(w, "    %s\n", g.Detail)
				}
			} else {
				fmt.Fprintln(w, "[-] No WAF detected by the generic detection")
			}
		}
	}
	fmt.Fprintf(w, "[~] Number of requests: %d (%s)\n", rep.Requests, time.Since(start).Round(time.Millisecond))

	if ex.finder != nil {
		renderOrigins(ctx, ex.finder, target, aux, c)
	}
	if ex.bypass {
		renderBypass(rep.WAFs, aux, c)
	}
	if ex.fuzzer != nil {
		renderFuzz(ctx, ex.fuzzer, target, aux, c)
	}
	return rep.Records(), true
}

func renderFuzz(ctx context.Context, f *fuzz.Fuzzer, target string, w io.Writer, c colors) {
	fmt.Fprintf(w, "%s[!] Active bypass fuzzing %s%s (authorized testing only).\n", c.R, target, c.E)
	res, err := f.Run(ctx, target)
	if err != nil && res == nil {
		fmt.Fprintf(w, "%s[-] Fuzzing failed: %v%s\n", c.R, err, c.E)
		return
	}
	fmt.Fprintf(w, "[+] Injected into %s %q; control response HTTP %d; %d requests sent.\n",
		res.Location, res.Param, res.ControlStatus, res.Requests)
	bypasses := res.Bypasses()
	if len(bypasses) == 0 {
		fmt.Fprintln(w, "[-] No tampered payload bypassed the WAF (of those whose raw form was blocked).")
		return
	}
	fmt.Fprintf(w, "%s[+] %d bypass(es) found:%s\n", c.G, len(bypasses), c.E)
	for _, b := range bypasses {
		fmt.Fprintf(w, "    %s%-5s%s via %s%-14s%s HTTP %d  %s\n",
			c.Y, b.Category, c.E, c.C, b.Tamper, c.E, b.Status, truncate(b.Value, 60))
	}
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\n", " "), "\r", "")
	if len(s) > n {
		return s[:n-1] + "…"
	}
	return s
}

func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func renderOrigins(ctx context.Context, f *origin.Finder, target string, w io.Writer, c colors) {
	res, err := f.Find(ctx, target)
	if err != nil {
		fmt.Fprintf(w, "%s[-] Origin discovery failed for %s: %v%s\n", c.R, target, err, c.E)
		return
	}
	fmt.Fprintf(w, "[+] Origin discovery for %s%s%s (domain %s):\n", c.B, target, c.E, res.Domain)
	fmt.Fprintf(w, "    Fronted IPs: %s\n", strings.Join(orDash(res.Fronted), ", "))
	var found bool
	for _, cand := range res.Candidates {
		if cand.Fronted {
			continue
		}
		found = true
		tag := ""
		switch {
		case cand.Confirmed:
			tag = c.G + " [confirmed origin]" + c.E
		case cand.Note != "":
			tag = " (" + cand.Note + ")"
		}
		hosts := ""
		if len(cand.Hostnames) > 0 {
			hosts = " " + strings.Join(cand.Hostnames, ",")
		}
		fmt.Fprintf(w, "    %s%-15s%s via %s%s%s\n", c.Y, cand.IP, c.E, strings.Join(cand.Sources, ","), hosts, tag)
	}
	if !found {
		fmt.Fprintln(w, "    No candidate origin IPs distinct from the fronted set were found.")
	}
}

func renderBypass(wafs []plugins.Plugin, w io.Writer, c colors) {
	fmt.Fprintf(w, "%s[!] Bypass guidance is a reference for AUTHORIZED testing only.%s\n", c.R, c.E)
	for _, p := range wafs {
		if b, ok := bypass.For(p.Product()); ok {
			fmt.Fprintf(w, "[+] Documented %s%s%s bypasses:\n", c.C, b.Product, c.E)
			for _, r := range b.References {
				fmt.Fprintf(w, "    - %s %s — %s (%s)\n      %s\n", r.Date, r.Vector, r.Summary, r.Credit, r.URL)
			}
		}
	}
	fmt.Fprintln(w, "[+] General evasion technique categories:")
	var cat bypass.Category
	for _, t := range bypass.Techniques() {
		if t.Category != cat {
			cat = t.Category
			fmt.Fprintf(w, "  %s%s%s\n", c.Y, cat, c.E)
		}
		fmt.Fprintf(w, "    - %s: %s\n", t.Name, t.Description)
	}
}

func orDash(s []string) []string {
	if len(s) == 0 {
		return []string{"-"}
	}
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func listWAFs(w io.Writer, format string, c colors) int {
	all := plugins.All()
	if strings.EqualFold(format, "json") {
		type item struct {
			ID           string `json:"id"`
			Name         string `json:"name"`
			Product      string `json:"product"`
			Manufacturer string `json:"manufacturer"`
		}
		items := make([]item, len(all))
		for i, p := range all {
			items[i] = item{p.ID, p.Name, p.Product(), p.Manufacturer()}
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(items)
		return exitOK
	}
	width := len("WAF Name")
	for _, p := range all {
		width = max(width, len(p.Product()))
	}
	fmt.Fprintf(w, "[+] Can test for these %d WAFs:\n\n", len(all))
	fmt.Fprintf(w, "%s  %-*s  %s%s\n", c.R, width, "WAF Name", "Manufacturer", c.E)
	fmt.Fprintf(w, "%s  %-*s  %s%s\n\n", c.R, width, "--------", "------------", c.E)
	for _, p := range all {
		fmt.Fprintf(w, "  %s%-*s%s  %s%s%s\n", c.Y, width, p.Product(), c.E, c.W, p.Manufacturer(), c.E)
	}
	return exitOK
}

func banner(c colors) string {
	// Figlet "Slant" wafgo. Backslashes are escaped for a double-quoted string.
	art := "" +
		"                 ____\n" +
		" _      ______ _/ __/___ _____\n" +
		"| | /| / / __ `/ /_/ __ `/ __ \\\n" +
		"| |/ |/ / /_/ / __/ /_/ / /_/ /\n" +
		"|__/|__/\\__,_/_/  \\__, /\\____/\n" +
		"                 /____/\n"
	return fmt.Sprintf("%s%s\n        %sgithub.com/miglen/wafgo%s  %s~ v%s ~%s\n\n",
		c.W, art, c.C, c.E, c.Y, wafgo.Version, c.E)
}

type colors struct{ W, Y, G, R, B, C, E string }

func newColors(on bool) colors {
	if !on {
		return colors{}
	}
	return colors{W: "\033[1;97m", Y: "\033[1;93m", G: "\033[1;92m", R: "\033[1;91m",
		B: "\033[1;94m", C: "\033[1;96m", E: "\033[0m"}
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}
