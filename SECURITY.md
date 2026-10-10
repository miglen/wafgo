# Security & responsible use

`wafgo` is a reconnaissance tool for **authorized** security testing: assets you
own, or for which you have explicit, written permission to test.

- Fingerprinting and generic detection send a handful of benign and
  intentionally-malformed requests to the target.
- Origin discovery queries public sources (DNS, crt.sh, and — only if you
  provide keys — Shodan/Censys) and, with `--origins-active`, connects to
  candidate hosts directly.
- The bypass reference (`-X`) only *describes and cites* public research; it
  does not generate or send attack traffic.

Do not use wafgo against systems you are not authorized to test. You are
responsible for complying with applicable laws and your engagement's scope.

To report a vulnerability in wafgo itself, open a private security advisory on
the GitHub repository.
