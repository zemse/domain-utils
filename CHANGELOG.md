# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-06-07

### Added
- Default lookup: `domain <name>` (no subcommand) checks availability and, for
  any name that's registered, also prints its full WHOIS/registration record.
  Accepts the same options and batch input as `check`.
- `check` — domain availability across all TLDs via the keyless `auto` backend
  (RDAP → port-43 WHOIS fallback).
- `whois` — registration data: registrar, dates, nameservers, EPP status.
- `dns` / `ns` — live DNS records over DNS-over-HTTPS (keyless).
- `email` — MX / SPF / DMARC / DKIM inspection.
- `tls` — live TLS certificate inspection (issuer, SANs, expiry; reads expired
  and self-signed certs).
- `price` and `check --price` — registration pricing via Porkbun's keyless
  pricing endpoint.
- `tlds` and multi-TLD spray on `check` — `--tlds`, `--category`, `--all-tlds`,
  backed by the embedded IANA TLD list and a curated category map.
- `--json` output for all commands.
- Batch input everywhere (positional args, `--file`, stdin), concurrent and
  de-duplicated.
- Backends: `auto`, `rdap`, `whois` (`backends` lists them).
- `dnssec` — DNSSEC status: parent `DS` records, zone `DNSKEY` count, and the
  resolver's `AD` (validated) bit.
- `ptr` — reverse-DNS (PTR) lookups for IPv4/IPv6 addresses.
- `propagation` — compare a DNS record across public resolvers (Google,
  Cloudflare, AdGuard, dns.sb) and flag divergence.
- `http` — HTTP redirect-chain trace with final status and HSTS / Server headers.
- `whois --expiring-within <DURATION>` — keep only domains expiring within a
  window (e.g. `30d`, `6w`, `1y`), sorted soonest-first.
- `completions <shell>` — generate shell completion scripts (bash, zsh, fish,
  powershell, elvish) via `clap_complete`.
- CI workflow (`.github/workflows/ci.yml`): fmt check, clippy `-D warnings`,
  build, and test on push / PR.

### Fixed
- DNS-over-HTTPS requests now have a 10s timeout, so an unresponsive resolver
  can no longer hang a run (notably in `propagation`).

[0.1.0]: https://github.com/zemse/domain-utils/releases/tag/v0.1.0
