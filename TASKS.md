# Tasks

Backlog for `domain-utils` (binary `domain`). Done items reflect what's committed
on `main`; pending items are enhancements, not part of the original brief.

## Done

- [x] Availability check (`check`) — keyless, all TLDs via `auto` (RDAP → port-43 WHOIS)
- [x] WHOIS / registration data (`whois`)
- [x] DNS records (`dns`) + nameservers shortcut (`ns`) over DNS-over-HTTPS
- [x] Email security (`email`) — MX / SPF / DMARC / DKIM
- [x] TLS certificate inspection (`tls`) — issuer, SANs, expiry (reads expired/self-signed)
- [x] Registration pricing (`price`) + `check --price` — Porkbun keyless endpoint
- [x] TLD categories + multi-TLD spray (`--tlds`, `--category`, `--all-tlds`, `tlds` cmd)
- [x] `--json` output across all commands
- [x] Batch input everywhere (args / `--file` / stdin), concurrent, de-duplicated
- [x] Backends: `auto`, `rdap`, `whois` (`backends` cmd)

## Pending

### Release / distribution
- [ ] Create GitHub remote and push `main`
- [ ] Tag and cut `v0.1.0` (GitHub release with notes)
- [ ] Publish to crates.io (`cargo install domain-utils`)
- [ ] CI (build + clippy + test on push)

### Pricing
- [ ] Multi-registrar pricing — currently Porkbun-only (indicative). Add keyed
      backends (GoDaddy, Gandi, Name.com, AWS Route 53) per `RESEARCH.md`
- [ ] Show cheapest across sources / price comparison

### Availability backends
- [ ] Keyed registrar backends from `RESEARCH.md` (Route 53, Gandi, Name.com, …)
      beyond the current `rdap` / `whois` / `auto`

### DNS / email / TLS extras
- [ ] DNS propagation diff across public resolvers (Google / Cloudflare / Quad9 / OpenDNS)
- [ ] Reverse DNS (`ptr <ip>`)
- [ ] DNSSEC status (AD flag / DS records)
- [ ] HTTP header / redirect-chain / HSTS check

### UX / scriptability
- [ ] Shell completions (`completions <shell>` via clap_complete)
- [ ] Expiry watch — `whois --expiring-within 30d`, sortable; pairs with `tls` days-to-expiry

## Notes
- Keyless-by-default is the project principle; keyed backends should be opt-in.
- Porkbun prices are retail/indicative, not a market minimum (labeled `source: porkbun`).
- Registrar API survey lives in `RESEARCH.md`.
