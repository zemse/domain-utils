//! Keyless port-43 WHOIS backend.
//!
//! Works for *any* TLD: the authoritative WHOIS server for a TLD is discovered
//! by asking `whois.iana.org` for the TLD (the IANA referral), then the domain
//! is queried against that server over TCP port 43. The response is free-text,
//! so availability and fields are extracted heuristically — markers and key
//! names vary by registry, so this is best-effort, unlike structured RDAP.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, lookup_host};
use tokio::sync::Mutex;
use tokio::time::timeout;

use super::{Availability, DomainInfo, normalize_domain, tld_of};

const IANA_WHOIS: &str = "whois.iana.org";
const QUERY_TIMEOUT: Duration = Duration::from_secs(10);

pub struct WhoisBackend {
    /// Per-process cache of TLD → WHOIS server (None = no server published).
    servers: Mutex<HashMap<String, Option<String>>>,
}

impl WhoisBackend {
    pub fn new() -> Self {
        Self {
            servers: Mutex::new(HashMap::new()),
        }
    }

    pub async fn lookup(&self, domain: &str) -> Result<DomainInfo> {
        let domain = normalize_domain(domain)?;
        let tld = tld_of(&domain).to_string();

        let server = self.whois_server(&tld).await?.ok_or_else(|| {
            anyhow!(
                "no WHOIS server is published for `.{tld}` (IANA has no referral), \
                 so availability can't be determined"
            )
        })?;

        let response = query(&server, &domain)
            .await
            .with_context(|| format!("querying WHOIS server {server} for {domain}"))?;

        Ok(parse_whois(domain, &response))
    }

    /// Resolve (and cache) the authoritative WHOIS server for a TLD via IANA.
    async fn whois_server(&self, tld: &str) -> Result<Option<String>> {
        if let Some(cached) = self.servers.lock().await.get(tld) {
            return Ok(cached.clone());
        }
        let referral = query(IANA_WHOIS, tld)
            .await
            .with_context(|| format!("querying IANA WHOIS for `.{tld}`"))?;
        let server = referral_server(&referral);
        self.servers
            .lock()
            .await
            .insert(tld.to_string(), server.clone());
        Ok(server)
    }
}

/// Send a single WHOIS query over TCP port 43 and read the full response.
async fn query(server: &str, request: &str) -> Result<String> {
    let fut = async {
        let mut stream = connect(server).await?;
        // Send query + CRLF in one write (some endpoints mishandle a split).
        stream
            .write_all(format!("{request}\r\n").as_bytes())
            .await?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await?;
        Ok::<_, anyhow::Error>(String::from_utf8_lossy(&buf).into_owned())
    };
    timeout(QUERY_TIMEOUT, fut).await.map_err(|_| {
        anyhow!(
            "WHOIS query to {server} timed out after {}s",
            QUERY_TIMEOUT.as_secs()
        )
    })?
}

/// Connect to a WHOIS server on port 43, preferring IPv4. Some registry hosts
/// (e.g. `whois.registry.co`) have a misconfigured IPv6 endpoint that answers
/// the TCP connect but speaks HTTP, so an IPv4 address is tried first.
async fn connect(server: &str) -> Result<TcpStream> {
    let addrs: Vec<SocketAddr> = lookup_host((server, 43))
        .await
        .with_context(|| format!("resolving {server}"))?
        .collect();
    if addrs.is_empty() {
        return Err(anyhow!("{server} resolved to no addresses"));
    }
    let ordered = addrs
        .iter()
        .filter(|a| a.is_ipv4())
        .chain(addrs.iter().filter(|a| a.is_ipv6()));
    let mut last_err = None;
    for addr in ordered {
        match TcpStream::connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(e) => last_err = Some(e),
        }
    }
    Err(anyhow!(
        "connecting to {server}:43: {}",
        last_err.expect("addrs non-empty implies an attempt")
    ))
}

/// Pull the referral WHOIS server out of an IANA response (`whois:`/`refer:`).
fn referral_server(response: &str) -> Option<String> {
    for line in response.lines() {
        let line = line.trim();
        for prefix in ["whois:", "refer:"] {
            if let Some(rest) = line.strip_prefix(prefix) {
                let server = rest.trim();
                if !server.is_empty() {
                    return Some(server.to_string());
                }
            }
        }
    }
    None
}

/// Parse a free-text WHOIS response into a [`DomainInfo`].
fn parse_whois(domain: String, text: &str) -> DomainInfo {
    let mut info = DomainInfo {
        domain,
        source: "whois",
        ..Default::default()
    };

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('%') || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        if value.is_empty() {
            continue;
        }

        match key.as_str() {
            "registrar" | "sponsoring registrar" | "registrar name" => {
                set_once(&mut info.registrar, value)
            }
            "creation date"
            | "created"
            | "created on"
            | "registered on"
            | "registration time"
            | "domain registration date"
            | "registered" => set_once(&mut info.registered, value),
            "registry expiry date"
            | "expiry date"
            | "expiration date"
            | "paid-till"
            | "expire"
            | "expires"
            | "expires on"
            | "registrar registration expiration date" => set_once(&mut info.expires, value),
            "updated date" | "last updated" | "last-update" | "changed" | "modified" => {
                set_once(&mut info.updated, value)
            }
            "name server" | "nserver" | "nameserver" | "name servers" => {
                // Some registries append IPs after the host; keep the host only.
                let ns = value
                    .split_whitespace()
                    .next()
                    .unwrap_or(value)
                    .trim_end_matches('.')
                    .to_ascii_lowercase();
                if !ns.is_empty() && !info.nameservers.contains(&ns) {
                    info.nameservers.push(ns);
                }
            }
            "domain status" | "status" | "state" => {
                let status = value.to_string();
                if !info.statuses.contains(&status) {
                    info.statuses.push(status);
                }
            }
            _ => {}
        }
    }

    info.availability = detect_availability(text, &info);
    info
}

fn set_once(slot: &mut Option<String>, value: &str) {
    if slot.is_none() {
        *slot = Some(value.to_string());
    }
}

/// Markers that indicate the registry has no record (domain is available).
const AVAILABLE_MARKERS: &[&str] = &[
    "no match",
    "not found",
    "no entries found",
    "no data found",
    "no object found",
    "nothing found",
    "no matching record",
    "domain not found",
    "not registered",
    "no such domain",
    "is available for registration",
    "available for registration",
    "status: available",
    "status: free",
];

fn detect_availability(text: &str, info: &DomainInfo) -> Availability {
    let lower = text.to_ascii_lowercase();

    // Concrete registration fields are the strongest signal — trust them over
    // stray marker words that can appear in a registry's legal preamble.
    let has_fields = info.registrar.is_some()
        || info.registered.is_some()
        || info.expires.is_some()
        || !info.nameservers.is_empty()
        || lower.contains("domain name:")
        || lower.contains("creation date");
    if has_fields {
        return Availability::Registered;
    }

    // No fields parsed: an explicit "not found / available" marker means free.
    if AVAILABLE_MARKERS.iter().any(|m| lower.contains(m)) {
        return Availability::Available;
    }

    // Terse status-only registries (e.g. DENIC `Status: connect`) report a
    // registered domain with nothing but a status line.
    if !info.statuses.is_empty() {
        return Availability::Registered;
    }

    Availability::Unknown
}
