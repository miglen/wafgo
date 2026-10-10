# wafgo usage

```
wafgo [options] url [url ...]
```

Targets may be given on the command line, with `-i`, or both. A target without
a scheme is treated as `https://`.

JSON input files must contain one array of objects with a `url` field. Trailing
whitespace is allowed; additional JSON documents or other trailing data are
rejected with an input error.

## Options

| Flag | Long | Description |
|------|------|-------------|
| `-v` | `--verbose` | Increase log verbosity; repeat for more (`-vvv` = debug). Logs go to stderr. |
| `-a` | `--findall` | Report every matching WAF, not just the first, and always run generic detection. |
| `-r` | `--noredirect` | Do not follow 3xx redirects. |
| `-t` | `--test` | Test for a single WAF by id (`cloudflare`) or full name (`"AireeCDN (Airee)"`). |
| `-o` | `--output` | Write results to a file; format inferred from extension. `-` means stdout. |
| `-f` | `--format` | Force results format: `json`, `csv` or `text`. Without `-o`, results go to stdout. |
| `-i` | `--input-file` | Read targets from a file (`.json`, `.csv` with a `url` column, or one per line). `-` means stdin. |
| `-l` | `--list` | List all detectable WAFs (add `-f json` for JSON). |
| `-p` | `--proxy` | Proxy URL: `http://host:8080`, `socks5://host:1080`, `http://user:pass@host:8080`. |
| `-H` | `--headers` | Replace the default headers with `Name: value` lines read from a file. |
| `-T` | `--timeout` | Per-request timeout in seconds (default 7). |
| `-c` | `--concurrency` | Number of targets scanned in parallel (default 10). |
|      | `--no-colors` | Disable ANSI colors (also honours the `NO_COLOR` environment variable). |
| `-q` | `--quiet` | Do not print the banner. |
| `-V` | `--version` | Print version and exit. |
| `-O` | `--origins` | Discover candidate origin IPs behind the WAF/CDN. |
|      | `--origins-active` | With `-O`, confirm candidates by connecting to them directly. |
|      | `--shodan-key` | Shodan API key for origin discovery (or `SHODAN_API_KEY`). |
|      | `--censys-id` / `--censys-secret` | Censys credentials (or `CENSYS_API_ID` / `CENSYS_API_SECRET`). |
| `-X` | `--bypass` | Show documented bypass techniques for detected WAFs (authorized testing only). |
|      | `--fuzz` | Actively send tampered payloads and report which bypass the WAF. Requires `--authorized-test`. |
|      | `--authorized-test` | Confirm you are authorized to send attack traffic to the target(s). |
|      | `--fuzz-where` | Injection point: `query` (default), `path`, `body` or `header`. |
|      | `--fuzz-param` | Parameter/header name to inject into (default: generated). |
|      | `--fuzz-categories` | Comma-separated payload categories, e.g. `xss,sqli` (default: all). |
|      | `--fuzz-tampers` | Comma-separated tampers to try (default: all). |
|      | `--fuzz-delay` | Delay between fuzz requests per worker, in seconds. |
|      | `--fuzz-workers` | Concurrent fuzz requests per target (default 5). |

## Enforcement: CDN vs. actively blocking WAF

A signature match means a WAF/CDN is *in the request path* — not necessarily
that it is blocking. wafgo compares the attack probe to the normal response and
labels each detection:

- **actively filtering** — the attack probe was blocked or answered differently
  (e.g. HTTP 403 vs 200, or a challenge/block page).
- **in path only** — the attack probes passed unchanged; the WAF/CDN is fronting
  the site but was not observed blocking (typical of Cloudflare used purely as a
  CDN).

This appears in the text output under each detection and as the `enforcement`
field/column in JSON and CSV (`blocking`, `not_observed`, or `unknown`).

## Active bypass fuzzing

`--fuzz` (with `--authorized-test`) establishes a control response, confirms the
raw attack payload is blocked, then tries tampered variants (case, URL/double-
URL/HTML-entity/unicode encoding, SQL comments, whitespace tricks, etc.) and
reports which ones the WAF lets through. Scope it with `--fuzz-where`,
`--fuzz-param`, `--fuzz-categories` and `--fuzz-tampers`; throttle with
`--fuzz-delay` / `--fuzz-workers`.

```bash
wafgo --fuzz --authorized-test --fuzz-where query --fuzz-param q https://example.com/search
```

## Output formats

The human-readable progress log always prints to stdout (unless results are sent
to stdout, in which case it moves aside). Machine-readable results are selected
with `-f`/`-o`.

File output is written to a temporary file in the destination directory, synced
and closed, then renamed into place. A failed write leaves an existing report
intact. New reports use owner-only permissions (`0600`); replacing a regular file
preserves its permission bits. Symbolic links and special files are rejected as
output destinations; use `-o -` for stdout. Replacing a file requires write access
to its directory. Rename atomicity depends on the operating system.

**text** (default) — right-aligned columns of URL, `Firewall (Manufacturer)` and
trigger URL.

**json** — an array of records:

```json
[
  {
    "url": "https://example.com",
    "detected": true,
    "trigger_url": "https://example.com/?abc=...",
    "firewall": "Cloudflare",
    "manufacturer": "Cloudflare Inc."
  }
]
```

**csv** — the same fields with a header row. The JSON/CSV schema matches
wafw00f's, so existing tooling keeps working.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Completed; results written. (Detection of a WAF is not an error.) |
| `1` | A target could not be scanned, or an input/output operation failed. |
| `2` | Usage error (bad flags, no target, unknown `--test` WAF). |

## Examples

### Scanning many hosts concurrently

Targets (from the command line and/or `-i`) are scanned by a worker pool;
`-c`/`--concurrency` (default 10) sets how many run at once. Per-target output
blocks stay intact and the result records keep input order regardless of
concurrency. For a large list, raise `-c`:

```bash
wafgo -c 50 -i hosts.txt -f json -o report.json   # 50 hosts in flight
```

```bash
# JSON report for a list of hosts, 25 at a time
wafgo -c 25 -f json -i hosts.txt -o report.json

# Only check whether a site is behind Akamai
wafgo -t akamai https://example.com

# Pipe hosts in, CSV out
cat hosts.txt | wafgo -i - -f csv

# Through a SOCKS proxy, no redirects, 15s timeout
wafgo -p socks5://127.0.0.1:1080 -r -T 15 https://example.com

# Fingerprint + origin discovery (active) + bypass reference
wafgo -a -O --origins-active -X https://example.com
```
