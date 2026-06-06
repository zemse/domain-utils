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
- [x] Reverse DNS (`ptr <ip>`) — IPv4/IPv6 over DoH
- [x] DNSSEC status (`dnssec`) — DS / DNSKEY records + AD (validated) bit
- [x] HTTP header / redirect-chain / HSTS check (`http`)
- [x] DNS propagation diff across public resolvers (`propagation`) — Google /
      Cloudflare / AdGuard / dns.sb (Quad9 & OpenDNS lack a JSON DoH endpoint)
- [x] Expiry watch — `whois --expiring-within 30d`, sorted soonest-first
- [x] Shell completions (`completions <shell>` via clap_complete)
- [x] CI (build + clippy + test on push) — `.github/workflows/ci.yml`

## Pending

### Release / distribution
- [x] Create GitHub remote and push `main` (github.com/zemse/domain-utils)
- [x] Tag and cut `v0.1.0` (GitHub release with notes)
- [x] Publish to crates.io (`cargo install domain-utils`)
- [ ] Publish v0.1.1 — version bump + CHANGELOG/README are committed & pushed to
      `main`, but the crates.io publish + `v0.1.1` tag + GitHub release are not
      cut yet (deferred). Run the `release` flow when ready.

### Pricing
- [x] Pricing is opt-in via `--pricing` (alias `--price`), off by default for
      every mode — Porkbun's keyless endpoint is slow (~15s, full-table only).
      When requested it's fetched concurrently with availability and cached on
      disk for 24h (platform cache dir; timestamp stored in-file). Price display
      shows the provider, e.g. `$10.81/yr (porkbun)`. (For v0.1.1.)
- [ ] Multi-registrar pricing — currently Porkbun-only (indicative). Add keyed
      backends (GoDaddy, Gandi, Name.com, AWS Route 53) per `RESEARCH.md`
      — **blocked: needs registrar API credentials** (and GoDaddy gates on 50+
      domains, Namecheap on IP-whitelisting). Can't be built+verified without keys.
- [ ] Show cheapest across sources / price comparison — **blocked on the above**
      (only one keyless price source exists today: Porkbun).

### Availability backends
- [ ] Keyed registrar backends from `RESEARCH.md` (Route 53, Gandi, Name.com, …)
      beyond the current `rdap` / `whois` / `auto`
      — **blocked: needs registrar API credentials** (same gate as keyed pricing).

## Notes
- Keyless-by-default is the project principle; keyed backends should be opt-in.
- Porkbun prices are retail/indicative, not a market minimum (labeled `source: porkbun`).
- Registrar API survey lives in `RESEARCH.md`.
- Propagation uses resolvers with a JSON DoH API; Quad9 (`:5053` unreachable;
  main endpoint is wire-format only) and OpenDNS (wire-format only) are omitted.
