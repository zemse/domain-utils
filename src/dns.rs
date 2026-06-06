//! DNS record lookups over DNS-over-HTTPS (DoH).
//!
//! Uses Google's public resolver (`https://dns.google/resolve`) by default,
//! which is keyless, returns JSON, and needs no local resolver configuration.
//! The same JSON DoH interface is used to query other public resolvers for
//! propagation diffs (see [`RESOLVERS`]) and to read the DNSSEC `AD` bit.

use std::net::IpAddr;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Record types queried by `dns` when none are given explicitly.
pub const DEFAULT_TYPES: &[&str] = &["A", "AAAA", "MX", "NS", "TXT"];

/// The default resolver used by single-resolver lookups (`dns`, `ns`, `email`).
const GOOGLE: &str = "https://dns.google/resolve";

/// A public DoH resolver exposing the JSON API (`application/dns-json`).
pub struct Resolver {
    pub name: &'static str,
    pub url: &'static str,
}

/// Public resolvers used for propagation diffs — all expose a JSON DoH endpoint.
///
/// Quad9 and OpenDNS are intentionally omitted: their public DoH endpoints serve
/// RFC 8484 wire-format only (no JSON variant), so they can't be queried the
/// same way. dns.sb stands in as a fourth independent operator.
pub const RESOLVERS: &[Resolver] = &[
    Resolver {
        name: "google",
        url: GOOGLE,
    },
    Resolver {
        name: "cloudflare",
        url: "https://cloudflare-dns.com/dns-query",
    },
    Resolver {
        name: "adguard",
        url: "https://dns.adguard-dns.com/resolve",
    },
    Resolver {
        name: "dns.sb",
        url: "https://doh.sb/dns-query",
    },
];

/// A single resolved DNS record.
#[derive(Debug, Clone, Serialize)]
pub struct DnsRecord {
    #[serde(rename = "type")]
    pub record_type: String,
    pub value: String,
    pub ttl: u32,
}

/// A resolver's full answer to one query: records plus DNSSEC-validation state.
pub struct DnsAnswer {
    pub records: Vec<DnsRecord>,
    /// The `AD` (Authenticated Data) bit — the resolver DNSSEC-validated the answer.
    pub ad: bool,
}

#[derive(Clone)]
pub struct DnsClient {
    client: reqwest::Client,
}

impl DnsClient {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .user_agent(concat!(
                env!("CARGO_PKG_NAME"),
                "/",
                env!("CARGO_PKG_VERSION")
            ))
            // Bound each request so an unresponsive resolver can't hang the run
            // (notably in propagation diffs across several endpoints).
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("failed to build HTTP client");
        Self { client }
    }

    /// Resolve a single record type for a name via the default resolver.
    /// Returns the answer records (which may include a CNAME chain), or an empty
    /// vec if there are none.
    pub async fn lookup(&self, name: &str, record_type: &str) -> Result<Vec<DnsRecord>> {
        Ok(self.query(GOOGLE, name, record_type).await?.records)
    }

    /// Like [`query`](Self::query) but against the default resolver — used when
    /// the full answer (`AD` bit, status) is needed, not just the records.
    pub async fn query_default(&self, name: &str, record_type: &str) -> Result<DnsAnswer> {
        self.query(GOOGLE, name, record_type).await
    }

    /// Resolve a record type against a specific DoH endpoint, returning the full
    /// answer (records, the `AD` bit, and the response status).
    pub async fn query(&self, endpoint: &str, name: &str, record_type: &str) -> Result<DnsAnswer> {
        let resp = self
            .client
            // Cloudflare/Quad9 require this header to return JSON; the others
            // ignore it, so it's safe to send to every resolver.
            .get(endpoint)
            .header("accept", "application/dns-json")
            .query(&[("name", name), ("type", record_type)])
            .send()
            .await
            .with_context(|| format!("querying DoH for {record_type} {name}"))?
            .error_for_status()
            .with_context(|| format!("DoH error for {record_type} {name}"))?;

        let body: DohResponse = resp
            .json()
            .await
            .with_context(|| format!("parsing DoH JSON for {record_type} {name}"))?;

        let records = body
            .answer
            .unwrap_or_default()
            .into_iter()
            .map(|a| DnsRecord {
                record_type: type_name(a.record_type),
                value: a.data,
                ttl: a.ttl,
            })
            .collect();
        Ok(DnsAnswer {
            records,
            ad: body.ad,
        })
    }
}

#[derive(Deserialize)]
struct DohResponse {
    #[serde(rename = "AD", default)]
    ad: bool,
    #[serde(rename = "Answer")]
    answer: Option<Vec<DohAnswer>>,
}

#[derive(Deserialize)]
struct DohAnswer {
    #[serde(rename = "type")]
    record_type: u16,
    #[serde(rename = "TTL")]
    ttl: u32,
    data: String,
}

/// Build the reverse-DNS lookup name for an IP address.
///
/// IPv4 `1.2.3.4` → `4.3.2.1.in-addr.arpa`; IPv6 is expanded to nibbles in
/// reverse under `ip6.arpa`.
pub fn reverse_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let mut s = String::with_capacity(72);
            for octet in v6.octets().iter().rev() {
                // Low nibble first, then high nibble (reverse order within the byte).
                s.push_str(&format!("{:x}.{:x}.", octet & 0xf, octet >> 4));
            }
            s.push_str("ip6.arpa");
            s
        }
    }
}

/// Map a numeric DNS record type to its mnemonic (falls back to the number).
fn type_name(t: u16) -> String {
    match t {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        43 => "DS",
        48 => "DNSKEY",
        46 => "RRSIG",
        257 => "CAA",
        other => return other.to_string(),
    }
    .to_string()
}
