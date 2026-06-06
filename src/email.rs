//! Email-security posture for a domain: MX, SPF, DMARC, and DKIM.
//!
//! All checks are DNS lookups over the shared DoH client, so this is keyless.
//! DKIM has no discovery mechanism in DNS, so a set of common selectors is
//! probed; absence here means "none of the common selectors", not "no DKIM".

use anyhow::Result;
use serde::Serialize;
use tokio::task::JoinSet;

use crate::dns::DnsClient;

/// Common DKIM selectors to probe (no DNS way to enumerate them).
const DKIM_SELECTORS: &[&str] = &[
    "google",
    "default",
    "selector1",
    "selector2",
    "k1",
    "s1",
    "dkim",
    "mail",
];

#[derive(Debug, Default, Serialize)]
pub struct EmailInfo {
    pub domain: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub mx: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spf: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spf_policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dmarc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dmarc_policy: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dkim_selectors: Vec<String>,
}

/// Gather MX/SPF/DMARC/DKIM for a domain.
pub async fn lookup(client: &DnsClient, domain: &str) -> Result<EmailInfo> {
    let dmarc_name = format!("_dmarc.{domain}");
    let (txt, dmarc_txt, mx) = tokio::join!(
        client.lookup(domain, "TXT"),
        client.lookup(&dmarc_name, "TXT"),
        client.lookup(domain, "MX"),
    );

    let mut info = EmailInfo {
        domain: domain.to_string(),
        ..Default::default()
    };

    info.mx = mx?.into_iter().map(|r| r.value).collect();

    let spf = txt?
        .into_iter()
        .map(|r| unquote(&r.value))
        .find(|v| v.to_ascii_lowercase().starts_with("v=spf1"));
    info.spf_policy = spf.as_deref().and_then(spf_policy).map(str::to_string);
    info.spf = spf;

    let dmarc = dmarc_txt?
        .into_iter()
        .map(|r| unquote(&r.value))
        .find(|v| v.to_ascii_lowercase().starts_with("v=dmarc1"));
    info.dmarc_policy = dmarc.as_deref().and_then(dmarc_policy);
    info.dmarc = dmarc;

    info.dkim_selectors = probe_dkim(client, domain).await;

    Ok(info)
}

/// Probe common DKIM selectors concurrently; return those that resolve to a key.
async fn probe_dkim(client: &DnsClient, domain: &str) -> Vec<String> {
    let mut set = JoinSet::new();
    for selector in DKIM_SELECTORS {
        let client = client.clone();
        let name = format!("{selector}._domainkey.{domain}");
        let selector = selector.to_string();
        set.spawn(async move {
            let found = client
                .lookup(&name, "TXT")
                .await
                .map(|recs| recs.iter().any(|r| is_dkim(&unquote(&r.value))))
                .unwrap_or(false);
            (selector, found)
        });
    }
    let mut found = Vec::new();
    while let Some(joined) = set.join_next().await {
        if let Ok((selector, true)) = joined {
            found.push(selector);
        }
    }
    found.sort();
    found
}

/// Strip a single pair of surrounding double quotes, if present.
fn unquote(value: &str) -> String {
    let v = value.trim();
    v.strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(v)
        .to_string()
}

/// Interpret the SPF `all` mechanism into a human-readable policy.
fn spf_policy(record: &str) -> Option<&'static str> {
    record.split_whitespace().find_map(|tok| match tok {
        "-all" => Some("fail (hard)"),
        "~all" => Some("softfail"),
        "?all" => Some("neutral"),
        "+all" => Some("pass-all (insecure)"),
        _ => None,
    })
}

/// Extract the DMARC `p=` policy tag value (none/quarantine/reject).
fn dmarc_policy(record: &str) -> Option<String> {
    record
        .split(';')
        .find_map(|part| part.trim().strip_prefix("p=").map(|v| v.trim().to_string()))
}

/// A selector "exists" only if it advertises a DKIM record with a non-empty
/// public key. An empty `p=` means the key was revoked, so it doesn't count.
fn is_dkim(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    if !lower.contains("dkim1") && !lower.contains("k=") && !lower.contains("p=") {
        return false;
    }
    value
        .split(';')
        .filter_map(|part| {
            let part = part.trim();
            part.strip_prefix("p=").or_else(|| part.strip_prefix("P="))
        })
        .any(|key| !key.trim().is_empty())
}
