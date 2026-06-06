# domain-utils

[![crates.io](https://img.shields.io/crates/v/domain-utils.svg)](https://crates.io/crates/domain-utils)
[![CI](https://github.com/zemse/domain-utils/actions/workflows/ci.yml/badge.svg)](https://github.com/zemse/domain-utils/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A small, fast CLI toolkit for domains: **check availability**, look up
**WHOIS / RDAP registration data**, see **registration pricing**, and inspect
**DNS records**, **email-security records**, **TLS certificates**, **DNSSEC**,
**reverse DNS**, **HTTP/redirect/HSTS**, and **DNS propagation** across public
resolvers — across multiple backends, keyless by default.

The default backend, **`auto`**, is **keyless** — no signup, no API key. It uses
RDAP where a TLD supports it and falls back to port-43 WHOIS otherwise, so it
covers every TLD. Backends can be selected explicitly with `--backend`.

The crate is published as **`domain-utils`**; it installs a binary named **`domain`**.

## Install

```sh
cargo install domain-utils   # or: cargo install --path .
```

## Usage

```sh
# Quick lookup (no subcommand): checks availability, and for any registered
# name also prints its full WHOIS/registration record.
domain example.com
domain example.com getme.dev acme.io

# Check availability only (default backend: auto = RDAP→WHOIS, keyless)
domain check example.com
domain check example.com getme.dev acme.io

# WHOIS / registration data
domain whois example.com

# Availability + price together
domain check mystartup --category popular --price
domain price com io dev ai          # registration pricing for TLDs

# DNS records (A, AAAA, MX, NS, TXT by default)
domain dns example.com
domain dns example.com --type MX,TXT      # only these record types
domain ns example.com                     # nameservers (shortcut for `dns -t NS`)

# Pick a backend explicitly
domain check example.com --backend whois

# DNS health
domain dnssec example.com                  # DNSSEC status (DS / DNSKEY / AD bit)
domain ptr 8.8.8.8 1.1.1.1                 # reverse DNS (PTR) for IPs
domain propagation example.com -t A        # compare a record across resolvers

# HTTP reachability: redirect chain, final status, HSTS header
domain http example.com

# Expiry watch: only domains expiring within a window, soonest first
domain whois --file portfolio.txt --expiring-within 30d

# List backends and whether each needs an API key
domain backends

# Shell completions (bash, zsh, fish, powershell, elvish)
domain completions zsh > ~/.zfunc/_domain
```

### Multi-TLD checks & categories

Check one name across many TLDs at once. Pick TLDs explicitly, by curated
**category**, or all of them:

```sh
domain check mystartup --tlds com,io,dev,ai      # explicit TLDs
domain check mystartup --category finance        # all finance TLDs
domain check mystartup -C tech,popular           # multiple categories
domain check mystartup --all-tlds                # every TLD (~1400; slow)

domain tlds                                      # list categories
domain tlds finance                              # TLDs in a category
domain tlds all                                  # every known TLD
```

The full IANA TLD list and the category map are baked into the binary (no
network needed); a test keeps every category entry pinned to a real delegation.

### Email security

`domain email <domain>` inspects a domain's mail-security posture over DNS
(keyless): MX records, SPF (with the `all` policy), DMARC (with the `p=`
policy), and DKIM. DKIM has no DNS discovery, so a set of common selectors is
probed — "none found" means none of those common selectors, not "no DKIM".

```text
$ domain email github.com
github.com
  ✓ MX      1 record(s)
  ✓ SPF     v=spf1 ... ~all  (softfail)
  ✓ DMARC   p=quarantine
  ✓ DKIM    selectors: google, k1, s1, selector1
```

### Pricing

`domain price <tld|domain>...` shows registration / renewal / transfer prices
via Porkbun's public, keyless pricing endpoint (USD; these are Porkbun's retail
prices — indicative, not a market minimum). Works by TLD, by `--category`, or
`--all`. Add `--price` to `check` to show the registration price next to each
available domain.

```text
$ domain price io dev ai
Porkbun pricing (USD/yr):
  .io             reg $28.12  renew $51.80  transfer $51.80
  .dev            reg $10.81  renew $12.87  transfer $12.87
  .ai             reg $82.70  renew $82.70  transfer $165.09

$ domain check mystartup --category popular --price
✓ mystartup.io  available  $28.12/yr
✓ mystartup.dev  available  $10.81/yr
...
```

### TLS certificate

`domain tls <domain>` opens a TLS connection and shows the leaf certificate:
subject, issuer, validity window, days-to-expiry (highlighted when expiring
soon or expired), and SANs. Trust is intentionally not verified, so expired or
self-signed certs are still inspected and flagged. Use `--port` for non-443.

```text
$ domain tls github.com
github.com:443
  subject:      github.com
  issuer:       Sectigo Public Server Authentication CA DV E36
  not after:    Aug  2 23:59:59 2026 +00:00
  expiry:       57 days left
  SANs:         github.com, www.github.com
```

### DNSSEC, reverse DNS & propagation

`domain dnssec <domain>` reports whether the parent zone publishes `DS` records
(a secure delegation), how many `DNSKEY` records the zone serves, and whether the
resolver set the `AD` (Authenticated Data) bit — i.e. it DNSSEC-validated the
answer.

```text
$ domain dnssec cloudflare.com
cloudflare.com  signed & validated
  DS records:   1
           2371 13 2 32996839A6D808AFE3EB4A...
  DNSKEY:       2
  AD bit:       set
```

`domain ptr <ip>...` does a reverse-DNS (PTR) lookup for one or more IPv4/IPv6
addresses. `domain propagation <domain>` queries the same record (default `A`,
override with `-t`) on several public resolvers (Google, Cloudflare, AdGuard,
dns.sb) and flags whether they agree — useful right after a DNS change.

```text
$ domain ptr 8.8.8.8
8.8.8.8  dns.google.

$ domain propagation example.com -t A
example.com (A)  consistent
  google       104.20.23.154, 172.66.147.243
  cloudflare   104.20.23.154, 172.66.147.243
  adguard      104.20.23.154, 172.66.147.243
  dns.sb       104.20.23.154, 172.66.147.243
```

(Quad9 and OpenDNS are omitted from propagation: their public DoH endpoints
serve wire-format only, with no JSON variant.)

### HTTP / redirects / HSTS

`domain http <url|domain>` traces the redirect chain hop by hop and reports the
final status plus the `Strict-Transport-Security` (HSTS) and `Server` headers. A
bare host defaults to `https://`.

```text
$ domain http github.com
https://github.com/
  200 https://github.com/
  HSTS:         max-age=31536000; includeSubdomains; preload
  server:       github.com
```

### Expiry watch

Add `--expiring-within <DURATION>` to `whois` to keep only domains whose
expiry falls within a window, sorted soonest-first — pair it with `tls`'s
days-to-expiry to watch renewals. Durations accept a bare number (days) or a
`d`/`w`/`m`/`y` suffix (e.g. `30`, `30d`, `6w`, `3m`, `1y`).

```sh
domain whois --file portfolio.txt --expiring-within 30d
```

### Shell completions

`domain completions <shell>` writes a completion script to stdout for `bash`,
`zsh`, `fish`, `powershell`, or `elvish`.

```sh
domain completions zsh > ~/.zfunc/_domain     # then ensure ~/.zfunc is on $fpath
domain completions bash > /etc/bash_completion.d/domain
```

### JSON output

Add `--json` to any command for machine-readable output (a JSON array), e.g.
`domain check example.com --json` or `domain dns example.com --json`. Pipe it to
`jq` to script around it.

### DNS records

`domain dns` fetches live records over DNS-over-HTTPS (keyless, no resolver
setup). Default types are `A,AAAA,MX,NS,TXT`; override with `--type` (`-t`),
comma-separated or repeated. `domain ns` is a shortcut for nameservers. Both
accept multiple domains / `--file` / stdin and run concurrently.

```text
$ domain dns example.com -t A,NS
example.com
  A      104.20.23.154  ttl 300
  NS     hera.ns.cloudflare.com.  ttl 21600
  NS     elliott.ns.cloudflare.com.  ttl 21600
```

### Batch checks

Domains can be passed as arguments, read from a file, and/or piped on stdin —
they're merged, de-duplicated, and looked up concurrently. Results print in
input order, followed by a summary line.

```sh
# Many domains at once
domain check example.com google.com acme.io rust-lang.org

# From a file (one per line, whitespace-separated; `#` starts a comment)
domain check --file domains.txt

# From stdin (no args, or `--file -`)
cat domains.txt | domain check

# Tune how many run concurrently (default: 10)
domain check --file domains.txt --concurrency 20
```

```text
$ domain check example.com google.com freeme-zxqw12345.com
✗ example.com  registered  (RESERVED-Internet Assigned Numbers Authority)
✗ google.com  registered  (MarkMonitor Inc.)
✓ freeme-zxqw12345.com  available
— 1 available · 2 registered
```

### Example

```text
# Default lookup: availability, plus WHOIS for registered names.
$ domain example.com freeme-zxqw12345.com
✗ example.com  registered  (RESERVED-Internet Assigned Numbers Authority)
example.com
  status:       registered
  registrar:    RESERVED-Internet Assigned Numbers Authority
  expires:      2026-08-13T04:00:00Z
  source:       rdap

✓ freeme-zxqw12345.com  available
— 1 available · 1 registered
```

```text
$ domain whois example.com
example.com
  status:       registered
  registrar:    RESERVED-Internet Assigned Numbers Authority
  registered:   1995-08-14T04:00:00Z
  expires:      2026-08-13T04:00:00Z
  nameservers:  a.iana-servers.net, b.iana-servers.net
  epp status:   client delete prohibited, client transfer prohibited
  source:       rdap
```

## How availability is determined (and a pitfall it avoids)

The default `auto` backend covers **every TLD** by combining two keyless sources:

1. **RDAP** maps the TLD to its registry RDAP server via the IANA bootstrap and
   queries it: **200 → registered**, **404 → available**. Crucially, a `404` is
   trusted as "available" **only** because the TLD was confirmed to have an RDAP
   service first. (A naive "404 = available" check would wrongly report
   registered `.io`/`.co` domains as free.)
2. **Port-43 WHOIS** handles the ~180 ccTLDs with no RDAP service (`.io`, `.co`,
   `.de`, `.me`, `.us`, …). The authoritative WHOIS server is discovered via
   IANA referral, then the free-text response is parsed heuristically. Because
   WHOIS formats vary by registry, this is best-effort and may return
   **unknown** for an unrecognized response (rather than guessing).

`auto` picks RDAP when the TLD supports it, otherwise WHOIS.

## Backends

| Backend | Key required | Covers | Notes |
|---------|--------------|--------|-------|
| `auto`  | no (keyless) | all TLDs | **Default.** RDAP where available, else port-43 WHOIS. |
| `rdap`  | no (keyless) | gTLDs + RDAP ccTLDs | Structured, authoritative. Errors on non-RDAP TLDs. |
| `whois` | no (keyless) | all TLDs | Port-43 WHOIS via IANA referral. Free-text, best-effort. |

Planned: keyed registrar backends (Porkbun, AWS Route 53, Gandi, Name.com) for
pricing. See `RESEARCH.md`.

## License

MIT
