# Architecture

## Packages

```
github.com/miglen/wafgo            engine, scan orchestration, output (engine.go, scan.go, output.go)
          .../plugins              WAF signatures + the Matcher interface
          .../origin               origin-IP discovery
          .../bypass               evasion technique / bypass reference
          .../cmd/wafgo            the CLI
tools/py2go                        wafw00f Python plugins  -> plugins/*_gen.go
tools/parity                       wafw00f (run in Python) -> testdata/parity.json
tools/nuclei2go                    nuclei waf-detect.yaml  -> plugins/nuclei_gen.go
```

## Detection model

A signature is a `plugins.Plugin` whose `Detect(Matcher) bool` inspects two
responses through the `Matcher` interface:

- **normal** — a plain GET (wafw00f's `rq`).
- **attack** — a GET carrying XSS+SQLi+LFI parameters (wafw00f's `attackres`).

`Matcher` exposes exactly the primitives the signatures need:
`MatchHeader`, `MatchCookie`, `MatchContent`, `MatchStatus`, `MatchReason`
(wafw00f), plus `MatchHeaderBlob` / `MatchResponseBlob` (nuclei header/response
parts). Each takes an `attack bool` selecting which response to read; when that
response is missing, every matcher returns false — the same semantics as
wafw00f's `None` responses.

`Site` (in `scan.go`) implements `Matcher` over the two captured responses.

### Signatures as generated code

The 172 wafw00f plugins are tiny declarative functions. `tools/py2go` parses
each with Python's `ast` module (never executing it) and emits an equivalent Go
function into `plugins/<id>_gen.go`. Anything the translator does not understand
aborts generation, so a silent mistranslation cannot happen. The priority order
from `wafprio.py` becomes `plugins/priority_gen.go`.

`tools/nuclei2go` converts the nuclei `waf-detect` matchers into
`plugins/nuclei_gen.go` as supplementary signatures (`Source: nuclei`). These
are kept separate from the wafw00f set so the parity guarantee is unaffected.

### Signature sets

- `plugins.Core()` — only the wafw00f signatures, in priority order. The parity
  test pins this at 172.
- `plugins.All()` — `Core()` followed by the nuclei signatures.
- `Identify` walks `All()` and de-duplicates by product, so a WAF detected by
  both sources is reported once.

## Why it is fast

wafw00f issues its probes sequentially. wafgo:

1. Sends the **normal** and **attack** request for a target concurrently, so a
   scan costs one round-trip instead of two-plus.
2. Runs the generic detection's four extra probes concurrently as well, then
   evaluates them in wafw00f's order — identical verdict, one round-trip.
3. Scans **multiple targets in parallel** with a worker pool (`-c`), while
   keeping per-target output blocks atomic and results in input order.
4. Reuses TCP/TLS connections via a shared `http.Transport`.
5. Compiles each signature regex once, and takes a **literal fast path**
   (lower-cased `bytes.Contains`) for the many signatures that are plain ASCII
   substrings. A property test checks the fast path against the regex engine.

## Correctness: the parity test

`tools/parity/gen_parity.py` runs the **original Python wafw00f plugins** against
thousands of synthetic responses (each generated to satisfy, or deliberately
miss, a specific matcher) and records the WAFs Python detects. `parity_test.go`
replays every case through the Go signatures and requires identical results.
Regenerate the fixture whenever signatures change:

```bash
make generate WAFW00F_SRC=/path/to/wafw00f
```

## Origin discovery

`origin.Finder.Find` merges candidate IPs from:

- the target host's current A/AAAA records (the *fronted* set),
- Certificate Transparency logs (crt.sh) resolved to IPs,
- common origin subdomains (`origin.`, `staging.`, `cpanel.`, …),
- Shodan / Censys when credentials are provided.

With `--origins-active`, each non-fronted candidate is fetched directly (TCP to
the candidate IP, original SNI + `Host`) and its response compared to the
fronted site to confirm it is the real origin.
