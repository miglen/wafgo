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
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: wafgo [options] url [url ...]\n\nExamples:\n"+
			"  wafgo https://example.com\n"+
			"  wafgo -a example.com example.org\n"+
			"  wafgo -f json -i targets.txt > results.json\n\nOptions:\n")
		fs.PrintDefaults()
	}
	return fs
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
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
	col := newColors(!cfg.noColors && os.Getenv("NO_COLOR") == "" && isTerminal(stdout))

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
		var (
			r    io.Reader = stdin
			name           = "stdin.txt"
		)
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

	records, failed := scanAll(ctx, eng, targets, only, max(cfg.concurrency, 1), human, col, log)

	if cfg.output != "" || resultsToStdout {
		out := stdout
		if !resultsToStdout {
			f, err := os.Create(cfg.output)
			if err != nil {
				fmt.Fprintf(stderr, "wafgo: %v\n", err)
				return exitError
			}
			defer f.Close()
			out = f
		}
		if err := wafgo.WriteRecords(out, format, records); err != nil {
			fmt.Fprintf(stderr, "wafgo: writing results: %v\n", err)
			return exitError
		}
	}
	if failed > 0 || ctx.Err() != nil {
		return exitError
	}
	return exitOK
}

// scanAll scans targets with a worker pool. Each target's log block is
// printed atomically as soon as it finishes; records keep input order.
func scanAll(ctx context.Context, eng *wafgo.Engine, targets []string, only *plugins.Plugin,
	workers int, human io.Writer, c colors, log *slog.Logger) ([]wafgo.Record, int) {

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
				var buf bytes.Buffer
				recs, ok := scanOne(ctx, eng, targets[i], only, &buf, c, log)
				results[i] = recs
				mu.Lock()
				if !ok {
					failed++
				}
				_, _ = human.Write(buf.Bytes())
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
	w io.Writer, c colors, log *slog.Logger) ([]wafgo.Record, bool) {

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
		if errors.Is(err, wafgo.ErrSiteDown) {
			fmt.Fprintf(w, "%s[-] Site %s appears to be down%s\n", c.R, target, c.E)
		} else {
			fmt.Fprintf(w, "%s[-] %s: %v%s\n", c.R, target, err, c.E)
		}
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
	return rep.Records(), true
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
	return fmt.Sprintf(`%s
     ,-.___,-.
     \_/_ _\_/     %s~ wafgo %s ~%s
       )O_O(       %s~ Sniffing Web Application Firewalls, fast ~%s
      { (_) }
       `+"`-^-'"+`
%s
`, c.W, c.G, wafgo.Version, c.W, c.Y, c.W, c.E)
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
