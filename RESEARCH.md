# Domain Registrar Research

Research into top domain registrars and whether they expose a **public/open API** for:
- **Availability** — check if a domain is available for registration
- **Pricing** — cost of registration / renewal / transfer
- **WHOIS** — lookup registrant/contact data for an arbitrary domain

> Scope note: nearly every "WHOIS" capability below is scoped to *domains you already own* in your own account — **no major registrar offers a clean public WHOIS-lookup API for arbitrary domains**. For arbitrary-domain WHOIS, use **RDAP** (`rdap.org`, registry RDAP servers) or a dedicated WHOIS service instead.

Last researched: 2026-06-06

---

## API capability matrix

| Registrar | Public API | Availability | Pricing | WHOIS (arbitrary) | Auth / access gate | Ease |
|---|---|---|---|---|---|---|
| **Porkbun** | ✅ JSON v3 | ✅ `checkDomain` | ✅ (`pricing/get` is **keyless**) | ❌ | Free keys; enable per-account/domain | 🟢 Easiest |
| **AWS Route 53 Domains** | ✅ | ✅ `CheckDomainAvailability` | ✅ `ListPrices` | ⚠️ own domains (`GetDomainDetail`) | AWS IAM SigV4; calls free | 🟢 Easy |
| **Gandi** | ✅ v5 REST | ✅ `/v5/domain/check` | ✅ (in `/check` response) | ❌ (own org only) | PAT (`Bearer pat_…`); account | 🟢 Easy |
| **Name.com** | ✅ Core v1/v4 | ✅ `domains:checkAvailability` | ✅ (in response) | ❌ (own only) | Basic auth user+token; account | 🟢 Easy |
| **NameSilo** | ✅ GET (XML/JSON) | ✅ `checkRegisterAvailability` | ✅ `getPrices` | ⚠️ own domains (`getDomainInfo`) | API key; account | 🟢 Easy |
| **Dynadot** | ✅ RESTful v2 | ✅ `search` | ✅ `domain_get_tld_price` | ✅ `whois_lookup` | Key + HMAC secret; account | 🟡 Medium |
| **Cloudflare Registrar** | ✅ | ✅ Domain Search/Check (new) | ✅ at-cost | ❌ | API token + account; ~34 TLDs | 🟡 Medium |
| **Namecheap** | ✅ XML | ✅ `domains.check` | ✅ `users.getPricing` | ❌ (contact mgmt only) | Key + **IP whitelist** + eligibility | 🟡 Medium |
| **GoDaddy** | ✅ REST | ✅ `/v1/domains/available` | ✅ (in response) | ❌ (own only) | sso-key; **needs 50+ domains** for availability | 🔴 Hard |
| **Enom** (Tucows) | ✅ HTTP | ✅ `Check` | ✅ `PE_*` / `GetTLDList` | ✅ `GetWhoisContact` (reseller scope) | Reseller UID/PW | 🔴 Reseller-only |
| **OpenSRS** (Tucows) | ✅ XML | ✅ `lookup` | ✅ `get_price` | ✅ (reseller scope) | Reseller key (signed) | 🔴 Reseller-only |
| **Hostinger** | ✅ REST | ✅ check availability | ⚠️ unclear | ❌ | Bearer token; account | 🟡 Medium |
| **IONOS** | ✅ | ❌ mgmt-only | ❌ | ❌ | API key; contract | 🔴 Poor fit |
| **Hover** (Tucows) | ✅ partner | ❌ landing page | ❌ | ❌ | App ID+secret; partner approval | 🔴 Poor fit |
| **Squarespace** (ex-Google Domains) | ✅ gated | ⚠️ invite-only | ❓ undocumented | ❓ undocumented | API key; invite-only | 🔴 Poor fit |

Legend: ✅ yes · ⚠️ partial / own-domains-only · ❌ no · ❓ unknown/undocumented

---

## Web providers to audit (frontend, next round)

Consumer-facing domain-search pages for the next-round frontend audit:

- [ ] **Porkbun** — https://porkbun.com/
- [ ] **AWS Route 53** — https://aws.amazon.com/route53/ (console-only, no public search page)
- [ ] **Gandi** — https://www.gandi.net/
- [ ] **Name.com** — https://www.name.com/
- [ ] **NameSilo** — https://www.namesilo.com/
- [ ] **Dynadot** — https://www.dynadot.com/
- [ ] **Cloudflare Registrar** — https://www.cloudflare.com/products/registrar/
- [ ] **Namecheap** — https://www.namecheap.com/domains/
- [ ] **GoDaddy** — https://www.godaddy.com/domains
- [ ] **Enom** — https://www.enom.com/
- [ ] **OpenSRS** — reseller-only (no consumer storefront)
- [ ] **Hostinger** — https://www.hostinger.com/domain-name-search
- [ ] **IONOS** — https://www.ionos.com/domains/domain-check
- [ ] **Hover** — https://www.hover.com/
- [ ] **Squarespace Domains** — https://domains.squarespace.com/

---

## Per-registrar detail

### Porkbun 🟢 (best open option)
- **API:** JSON REST v3 — https://porkbun.com/api/json/v3/documentation (OpenAPI: https://porkbun.com/api/json/v3/spec)
- **Availability:** `POST /api/json/v3/domain/checkDomain/{domain}` → `avail: "yes"/"no"` + pricing. Rate-limited.
- **Pricing:** `GET /api/json/v3/pricing/get` → all TLDs (reg/renew/transfer USD). **No auth required** — the only keyless endpoint here.
- **WHOIS:** ❌ none.
- **Auth:** `apikey` + `secretapikey` in JSON body. Free keys; must enable API access in account + per-domain.

### AWS Route 53 Domains 🟢 (best no-approval programmatic option)
- **API:** https://docs.aws.amazon.com/Route53/latest/APIReference/API_Operations_Amazon_Route_53_Domains.html
- **Availability:** `CheckDomainAvailability` (+ `CheckDomainTransferability`, `GetDomainSuggestions`). Returns `AVAILABLE`/`UNAVAILABLE`/`UNAVAILABLE_PREMIUM`/`RESERVED`/`PENDING`/`DONT_KNOW`.
- **Pricing:** `ListPrices` (reg/transfer/renewal/restoration by TLD).
- **WHOIS:** ⚠️ `GetDomainDetail` — own AWS-account domains only.
- **Auth:** AWS SigV4 (IAM). API calls free; pay only on register/transfer/renew. No reseller program.
- **Gotcha:** only Route 53-supported TLDs; may return `PENDING`/`DONT_KNOW` (retry).

### Gandi 🟢
- **API:** https://api.gandi.net/docs/domains/ — base `https://api.gandi.net/v5/domain`
- **Availability + pricing in one call:** `GET /v5/domain/check?name=<domain>` → rich pricing (before/after tax, durations, discounts, phase pricing).
- **WHOIS:** ❌ (`/v5/domain/domains/{domain}` is own-org only).
- **Auth:** Personal Access Token (`Authorization: Bearer pat_…`). Legacy `Apikey` auth deprecated.

### Name.com 🟢
- **API:** https://docs.name.com/api/v1/reference/domains/check-availability
- **Availability + pricing:** `POST /core/v1/domains:checkAvailability` (≤50 domains/call) → `purchasePrice`, `renewalPrice`, `premium` flag. (Don't URL-encode the `:`.)
- **WHOIS:** ❌ (own account only).
- **Auth:** HTTP Basic — username + API token. Sandbox `api.dev.name.com`; prod `api.name.com`. ~20 req/s.

### NameSilo 🟢
- **API:** https://www.namesilo.com/api-reference — base `https://www.namesilo.com/api/OPERATION?version=1&type=xml&key=…`
- **Availability:** `checkRegisterAvailability` (comma-separated; available/unavailable/invalid groups + `price`).
- **Pricing:** `getPrices` (per-TLD reg/renew/transfer).
- **WHOIS:** ⚠️ `getDomainInfo` — own domains only (separate public web WHOIS tool exists).
- **Auth:** single API key; GET-only over HTTPS. Sandbox on request.

### Dynadot 🟡
- **API:** RESTful v2 (launched 2025-10-09) — https://www.dynadot.com/domain/api-document — base `https://api.dynadot.com/restful/v2/`
- **Availability:** `search`. **Pricing:** `domain_get_tld_price`. **WHOIS:** ✅ `whois_lookup` (rare — closest to a real WHOIS API).
- **Auth:** API key + secret; `Bearer` + `X-Signature` (HMAC-SHA256) for write ops. Tiered rate limits.
- **Note:** older command-style API (`api3.xml?command=…`) still exists; most third-party libs target it.

### Cloudflare Registrar 🟡
- **API:** https://developers.cloudflare.com/registrar/ — https://developers.cloudflare.com/api/resources/registrar/
- **Availability:** Domain Search + Domain Check (newer capability). **Pricing:** at-cost, no markup.
- **WHOIS:** ❌. **Auth:** API token + Account ID.
- **Gotcha:** programmatic registration limited to ~34 TLDs; async workflow + polling.

### Namecheap 🟡
- **API:** https://www.namecheap.com/support/api/intro/ (XML-over-HTTP, query-string GET)
- **Availability:** `namecheap.domains.check` (+ `IsPremiumName`). **Pricing:** `namecheap.users.getPricing`.
- **WHOIS:** ❌ (contact mgmt only — `domains.getContacts`/`setContacts`).
- **Auth:** `ApiUser`/`ApiKey`/`UserName`/`ClientIp`; **calling IP must be whitelisted**.
- **Gotcha:** API must be manually enabled; eligibility = 20+ domains OR ≥$50 balance OR ≥$50 spent in 2 yrs. (Live docs return 403 to scrapers — verify current thresholds manually.)

### GoDaddy 🔴
- **API:** https://developer.godaddy.com/doc/endpoint/domains
- **Availability:** `GET /v1/domains/available?domain=…` (+ bulk `POST`); pricing in response.
- **WHOIS:** ❌ (`/v1/domains/{domain}` = own account only).
- **Auth:** `Authorization: sso-key {KEY}:{SECRET}`. OTE sandbox `api.ote-godaddy.com`.
- **Gotcha (major):** Availability/pricing API requires **50+ domains in account** — effectively off-limits for small users.

### Enom (Tucows) 🔴 reseller-only
- **API:** https://www.enom.com/reseller/documentation/ · catalog https://cp.enom.com/APICommandCatalog/ — base `https://reseller.enom.com/interface.asp`
- **Availability:** `Check` (EPP) + `GetNameSuggestions`. **Pricing:** `PE_GetResellerPrice`/`PE_GetRetailPricing`/`GetTLDList`. **WHOIS:** ✅ `GetWhoisContact` (reseller scope).
- **Auth:** reseller UID/PW (in query string — legacy). Approved reseller account required.

### OpenSRS (Tucows) 🔴 reseller-only
- **API:** https://domains.opensrs.guide/ (XML-over-HTTPS POST)
- **Availability:** `lookup` (210=available, 211=taken, `has_claim`, premium reason) + `name_suggest`. **Pricing:** `get_price` (incl. OpenSRS fee + ICANN, per-period). **WHOIS:** ✅ `get_domain` (reseller scope).
- **Auth:** reseller username + private key (MD5-signed). Approved reseller account required.

### Hostinger 🟡
- **API:** https://developers.hostinger.com/ (REST; PHP/Python/JS SDKs + official MCP server)
- **Availability:** ✅ "Check domain availability" endpoint. **Pricing:** ⚠️ no clear standalone TLD-pricing endpoint. **WHOIS:** ❌.
- **Auth:** Bearer token from hPanel; account required.

### IONOS 🔴 poor fit
- **API:** https://developer.hosting.ionos.com/docs/domains — management-only for owned domains. No availability/pricing/WHOIS lookups. Consumer check: https://www.ionos.com/domains/domain-check

### Hover (Tucows) 🔴 poor fit
- **API:** https://partners.hover.com/ — partner-approval gated; ~4 commands centered on vouchers/Connect + "get info on a domain" (partner scope). No general availability/pricing/WHOIS. (Don't confuse with `developers.hover.to`, an unrelated 3D-modeling company.)

### Squarespace Domains (ex-Google Domains) 🔴 poor fit
- **API:** https://developers.squarespace.com/ — lists "Domains Search API" + "Domains Management API" but effectively **invite-only and undocumented publicly**. Consumer: https://domains.squarespace.com/

---

## Recommendations

- **For an availability + pricing checker:** start with **Porkbun** (free keys, public keyless pricing, simple JSON) and **AWS Route 53** (`CheckDomainAvailability` + `ListPrices`, no reseller approval). **Gandi** and **Name.com** are the cleanest "availability+pricing in one call."
- **Avoid for small projects:** GoDaddy (50-domain gate), Namecheap (eligibility + IP whitelist), IONOS/Hover/Squarespace (no real public availability API).
- **For full availability+pricing+WHOIS:** OpenSRS / Enom — but both need approved reseller accounts.
- **For arbitrary-domain WHOIS specifically:** don't rely on registrar APIs — use **RDAP** (`https://rdap.org/domain/<domain>`) or registry RDAP servers; **Dynadot's `whois_lookup`** is the lone registrar exception.
