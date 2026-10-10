# wafgo

**Fast Web Application Firewall fingerprinting — a single static binary.**

wafgo identifies which WAF or CDN sits in front of a site, tells you whether it
is **actively blocking** or just **fronting** the origin (CDN/proxy in path),
finds candidate **origin IPs** behind it, and can actively **fuzz** for bypasses.
It scans many targets concurrently and ships as a ~9 MB `scratch` image with no
shell or OS packages.

- 264 WAF/CDN signatures
- CDN-vs-enforcing-WAF verdict on every detection
- Origin-IP discovery (DNS, crt.sh, Shodan/Censys)
- Active bypass fuzzer (authorized testing only)
- Text / JSON / CSV output; library API for Go

> ⚠️ Authorized use only — scan systems you own or have permission to test.

## Tags

- `latest`, `0.1.0` — multi-arch (`linux/amd64`, `linux/arm64`)

## Quick start

```bash
# fingerprint a site
docker run --rm miglen/wafgo https://example.com

# find every matching WAF, JSON output
docker run --rm miglen/wafgo -a -f json https://example.com

# scan many targets from a local file (mounted in)
docker run --rm -v "$PWD:/data" miglen/wafgo -i /data/targets.txt -f csv
```

The entrypoint is the `wafgo` binary, so append any flags directly. Run
`docker run --rm miglen/wafgo -h` for the full list.

## Image details

- Base: `FROM scratch` (static `CGO_ENABLED=0` binary + CA roots only)
- Runs as non-root (UID 65534)
- Architectures: `linux/amd64`, `linux/arm64`

## Links

- Source & docs: https://github.com/miglen/wafgo
- Usage: https://github.com/miglen/wafgo/blob/main/docs/USAGE.md

BSD 3-Clause licensed. Credits: wafw00f (Enable Security), nuclei-templates
(ProjectDiscovery), WhatWaf, cloudbunny, PayloadsAllTheThings.
