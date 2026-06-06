//! DNSSEC status for a domain.
//!
//! Reads the delegation signer (`DS`) records published by the parent zone and
//! the zone's own `DNSKEY` records over DoH, plus the resolver's `AD`
//! (Authenticated Data) bit, which is set when the resolver successfully
//! DNSSEC-validated the answer. A domain is considered signed when the parent
//! delegation carries DS records.

use anyhow::Result;
use serde::Serialize;

use crate::dns::{DnsClient, DnsRecord};

#[derive(Debug, Serialize)]
pub struct DnssecInfo {
    pub domain: String,
    /// True when the parent zone publishes DS records (a secure delegation).
    pub signed: bool,
    /// True when the resolver DNSSEC-validated the answer (the `AD` bit).
    pub validated: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ds: Vec<DnsRecord>,
    /// Number of DNSKEY records the zone publishes.
    pub dnskey_count: usize,
}

/// Resolve the DNSSEC posture of a single domain.
pub async fn inspect(client: &DnsClient, domain: &str) -> Result<DnssecInfo> {
    // DS lives in the parent zone; querying it for the domain returns the
    // delegation's DS RRset (with AD set when the resolver validated it).
    let ds_answer = client.query_default(domain, "DS").await?;
    let dnskey = client.lookup(domain, "DNSKEY").await?;

    Ok(DnssecInfo {
        domain: domain.to_string(),
        signed: !ds_answer.records.is_empty(),
        validated: ds_answer.ad,
        ds: ds_answer.records,
        dnskey_count: dnskey.len(),
    })
}
