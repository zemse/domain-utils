# domain-rs

A small, fast CLI to **check domain availability** and look up **WHOIS / registration data** across multiple registrar backends.

The default backend, **`rdap`**, is **keyless** — no signup, no API key. It uses the
IANA RDAP bootstrap registry to query each TLD's authoritative registry server
directly. Additional backends (some requiring an API key) can be selected with
`--backend`.

The crate is published as **`domain-rs`**; it installs a binary named **`domain`**.

## Install

```sh
cargo install domain-rs   # or: cargo install --path .
```

## Usage

```sh
# Check availability (default backend: rdap, keyless)
domain check example.com
domain check example.com getme.dev acme.io

# WHOIS / registration data
domain whois example.com

# Pick a backend explicitly
domain check example.com --backend rdap

# List backends and whether each needs an API key
domain backends
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

`rdap` maps the domain's TLD to its registry RDAP server via the IANA bootstrap
registry, then queries that server:

- registry returns **200** → **registered**
- registry returns **404** → **available**

Crucially, a `404` is treated as "available" **only after** confirming the TLD has
an RDAP service. TLDs with no RDAP service (e.g. `.de`, `.io`, `.co`, `.me`, `.us`)
resolve to **unknown** rather than a false "available", and the CLI tells you to
try another backend. (A naive "404 = available" check would wrongly report
registered `.io`/`.co` domains as free.)

## Backends

| Backend | Key required | WHOIS | Notes |
|---------|--------------|-------|-------|
| `rdap`  | no (keyless) | yes   | Default. IANA bootstrap → registry RDAP. gTLDs + ~70 ccTLDs. |

Planned: a port-43 WHOIS fallback for non-RDAP ccTLDs, and keyed registrar
backends (Porkbun, AWS Route 53, Gandi, Name.com) for pricing. See `RESEARCH.md`.

## License

MIT
