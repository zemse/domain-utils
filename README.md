# domain-utils

A small, fast CLI toolkit for domains: **check availability**, look up
**WHOIS / RDAP registration data**, and (soon) inspect **DNS records** — across
multiple backends.

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
# Check availability (default backend: auto = RDAP→WHOIS, keyless)
domain check example.com
domain check example.com getme.dev acme.io

# WHOIS / registration data
domain whois example.com

# DNS records (A, AAAA, MX, NS, TXT by default)
domain dns example.com
domain dns example.com --type MX,TXT      # only these record types
domain ns example.com                     # nameservers (shortcut for `dns -t NS`)

# Pick a backend explicitly
domain check example.com --backend whois

# List backends and whether each needs an API key
domain backends
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
$ domain check example.com freeme-zxqw12345.com
✗ example.com  registered  (RESERVED-Internet Assigned Numbers Authority)
✓ freeme-zxqw12345.com  available
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
