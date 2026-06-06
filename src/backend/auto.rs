//! Default backend: use RDAP where the TLD supports it (structured and
//! authoritative), otherwise fall back to port-43 WHOIS. Together they cover
//! every TLD with a published registry service.

use anyhow::Result;

use super::rdap::RdapBackend;
use super::whois::WhoisBackend;
use super::{DomainInfo, normalize_domain, tld_of};

pub struct AutoBackend {
    rdap: RdapBackend,
    whois: WhoisBackend,
}

impl AutoBackend {
    pub fn new() -> Self {
        Self {
            rdap: RdapBackend::new(),
            whois: WhoisBackend::new(),
        }
    }

    pub async fn lookup(&self, domain: &str) -> Result<DomainInfo> {
        let normalized = normalize_domain(domain)?;
        let tld = tld_of(&normalized);
        // Prefer RDAP when the TLD publishes it; on a bootstrap failure, fall
        // back to WHOIS (which also handles gTLDs) rather than erroring out.
        if self.rdap.has_rdap(tld).await.unwrap_or(false) {
            self.rdap.lookup(&normalized).await
        } else {
            self.whois.lookup(&normalized).await
        }
    }
}
