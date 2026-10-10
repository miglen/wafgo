# wafgo usage

```
wafgo [options] url [url ...]
```

Targets may be given on the command line, with `-i`, or both. A target without
a scheme is treated as `https://`.

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

## Output formats

The human-readable progress log always prints to stdout (unless results are sent
to stdout, in which case it moves aside). Machine-readable results are selected
with `-f`/`-o`.

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
| `1` | A target could not be scanned, or a file/flag error occurred. |
| `2` | Usage error (bad flags, no target, unknown `--test` WAF). |

## Examples

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
