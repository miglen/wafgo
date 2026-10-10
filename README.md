<h1 align="center">wafgo</h1>

<p align="center"><b>Fast Web Application Firewall fingerprinting — a Go port of <a href="https://github.com/EnableSecurity/wafw00f">wafw00f</a>.</b></p>

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.23+-00ADD8.svg">
  <img src="https://img.shields.io/badge/License-BSD%203--Clause-orange.svg">
  <img src="https://img.shields.io/badge/signatures-264-blue.svg">
</p>

`wafgo` identifies which WAF or CDN protects a site, finds candidate origin IPs
hiding behind it, and points to documented evasion techniques — as a single
static binary that scans many targets concurrently.

It reuses wafw00f's detection logic and signatures (ported automatically, with
a parity test proving identical results) and adds the WAF fingerprints from
[nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
(`waf-detect`, inspired by [WhatWaf](https://github.com/Ekultek/WhatWaf)).

> ⚠️ **Authorized use only.** Fingerprinting, origin discovery and bypass
> research are for systems you own or have explicit permission to test.

## Features

- **264 WAF/CDN signatures** — 172 from wafw00f + 92 from nuclei, de-duplicated by product.
- **Fast.** Probe requests for a target run concurrently over reused
  connections; multiple targets scan in parallel (`-c`). A typical scan is one
  round-trip of wall-clock time instead of six sequential ones.
- **Generic detection** — behavioural heuristics when no signature matches.
- **Origin IP discovery** (`-O`) — DNS, Certificate Transparency (crt.sh),
  common origin subdomains, and optional Shodan/Censys; optional direct-connect
  confirmation. Inspired by [cloudbunny](https://github.com/Warflop/cloudbunny).
- **Bypass reference** (`-X`) — evasion technique categories plus publicly
  documented, per-WAF bypasses citing
  [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings).
- **wafw00f-compatible CLI & output** — text, JSON and CSV; file input/output.
- **Library** — `import "github.com/miglen/wafgo"`.

## Install

```bash
go install github.com/miglen/wafgo/cmd/wafgo@latest
```

Or build from source:

```bash
git clone https://github.com/miglen/wafgo && cd wafgo
make build        # produces ./wafgo
```

Prebuilt binaries for Linux/macOS/Windows are attached to each
[release](https://github.com/miglen/wafgo/releases).

## Usage

```bash
wafgo https://example.com                 # fingerprint one site
wafgo -a example.com example.org          # find every matching WAF
wafgo -i targets.txt -f json > out.json   # many targets, JSON to stdout
wafgo -l                                  # list detectable WAFs
```

Identify the WAF, its origin, and documented bypasses in one run:

```bash
wafgo -a -O -X https://example.com
```

```
[*] Checking https://example.com
[+] The site https://example.com is behind Cloudflare (Cloudflare Inc.) WAF.
[+] Origin discovery for https://example.com (domain example.com):
    Fronted IPs: 104.16.132.229, 104.16.133.229
    203.0.113.10   via host:staging.example.com staging.example.com [confirmed origin]
[+] Documented Cloudflare bypasses:
    - 2021-01-25 Reflected XSS — SVG/animate-based vector ... (@bohdansec)
```

See [docs/USAGE.md](docs/USAGE.md) for every flag and output format, and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how detection and the code
generators work.

### Origin discovery

`-O` gathers candidate origin IPs without touching the target's WAF; add
`--origins-active` to confirm a candidate by connecting to it directly (with the
original `Host`/SNI) and comparing the response to the fronted site. Shodan and
Censys are used when credentials are supplied via flags or the
`SHODAN_API_KEY`, `CENSYS_API_ID` and `CENSYS_API_SECRET` environment variables.

### Bypass reference

`-X` prints, for each detected WAF, the publicly documented bypasses (with
credit and a link to the primary source) plus a catalog of general evasion
technique *categories*. wafgo describes techniques and cites research; it does
not generate or send attack traffic.

## Docker

```bash
docker build -t wafgo .
docker run --rm wafgo https://example.com
docker run --rm wafgo -a -f json https://example.com
```

The image is built `FROM scratch` (static binary, non-root, CA roots included),
so it is only a few megabytes and has no shell or OS packages.

## Library

```go
package main

import (
	"context"
	"fmt"

	"github.com/miglen/wafgo"
)

func main() {
	eng, _ := wafgo.New(wafgo.Options{FindAll: true})
	rep, err := eng.Scan(context.Background(), "https://example.com")
	if err != nil {
		panic(err)
	}
	for _, w := range rep.WAFs {
		fmt.Println(w.Name)
	}
}
```

## Updating signatures

Signatures are generated, never hand-edited. With a local wafw00f checkout:

```bash
make generate WAFW00F_SRC=/path/to/wafw00f
```

This re-runs the translators (`tools/py2go`, `tools/parity`, `tools/nuclei2go`)
and the test suite. The nuclei input lives at
[`testdata/nuclei-waf-detect.yaml`](testdata/nuclei-waf-detect.yaml).

## Credits & license

`wafgo` is BSD 3-Clause licensed (see [LICENSE](LICENSE)). Detection logic and
signatures derive from **wafw00f** by Enable Security (BSD 3-Clause) and from
**nuclei-templates** by ProjectDiscovery. Origin discovery is inspired by
**cloudbunny**; the bypass reference cites **WhatWaf** and
**PayloadsAllTheThings**. All trademarks belong to their owners.
