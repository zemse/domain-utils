# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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

[Unreleased]: https://github.com/zemse/domain-utils/commits/main
