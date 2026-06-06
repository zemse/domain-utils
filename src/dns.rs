//! DNS record lookups over DNS-over-HTTPS (DoH).
//!
//! Uses Google's public resolver (`https://dns.google/resolve`), which is
//! keyless, returns JSON, and needs no local resolver configuration. This lets
//! the CLI fetch live records (A, AAAA, MX, NS, TXT, …) over the same HTTPS
//! stack the other backends use.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Record types queried by `dns` when none are given explicitly.
pub const DEFAULT_TYPES: &[&str] = &["A", "AAAA", "MX", "NS", "TXT"];

const DOH_ENDPOINT: &str = "https://dns.google/resolve";

/// A single resolved DNS record.
#[derive(Debug, Clone, Serialize)]
pub struct DnsRecord {
    #[serde(rename = "type")]
    pub record_type: String,
    pub value: String,
    pub ttl: u32,
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
            .build()
            .expect("failed to build HTTP client");
        Self { client }
    }

    /// Resolve a single record type for a name. Returns the answer records
    /// (which may include a CNAME chain), or an empty vec if there are none.
    pub async fn lookup(&self, name: &str, record_type: &str) -> Result<Vec<DnsRecord>> {
        let resp = self
            .client
            .get(DOH_ENDPOINT)
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
        Ok(records)
    }
}

#[derive(Deserialize)]
struct DohResponse {
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
        257 => "CAA",
        other => return other.to_string(),
    }
    .to_string()
}
