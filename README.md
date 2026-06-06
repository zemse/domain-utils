# domain-cli

A small, fast CLI to **check domain availability** and look up **WHOIS / registration data** across multiple registrar backends.

The default backend, **`rdap`**, is **keyless** — no signup, no API key. It uses the
IANA RDAP bootstrap registry to query each TLD's authoritative registry server
directly. Additional backends (some requiring an API key) can be selected with
`--backend`.

## Install

```sh
cargo install --path .
```

This builds a binary named **`domain`**.

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
