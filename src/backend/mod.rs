//! Backends that resolve domain availability / registration data.
//!
//! Backends are dispatched through the [`Backend`] enum rather than a `dyn`
//! trait object so that adding a new backend is a single match arm and the
//! whole set is known at compile time. All current backends are keyless; the
//! default [`auto`](auto) routes RDAP → WHOIS so every TLD resolves. Future
//! keyed backends (Porkbun, Route 53, …) would add a `requires_api_key` arm.

mod auto;
mod rdap;
mod whois;

use anyhow::{Result, bail};
use serde::Serialize;

use self::auto::AutoBackend;
use self::rdap::RdapBackend;
use self::whois::WhoisBackend;

/// All backend names known to the CLI, in display order.
pub const BACKENDS: &[BackendInfo] = &[
    BackendInfo {
        name: "auto",
        requires_api_key: false,
        supports_whois: true,
        blurb: "RDAP where available, else port-43 WHOIS — covers all TLDs (default).",
    },
    BackendInfo {
        name: "rdap",
        requires_api_key: false,
        supports_whois: true,
        blurb: "Keyless RDAP via the IANA bootstrap (gTLDs + RDAP-enabled ccTLDs).",
    },
    BackendInfo {
        name: "whois",
        requires_api_key: false,
        supports_whois: true,
        blurb: "Keyless port-43 WHOIS via IANA referral — covers all TLDs.",
    },
];

/// Static metadata about a backend, used by `domain backends`.
pub struct BackendInfo {
    pub name: &'static str,
    pub requires_api_key: bool,
    pub supports_whois: bool,
    pub blurb: &'static str,
}

/// Whether a domain is available, taken, or could not be determined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Availability {
    /// The registry has no record of the domain — it can be registered.
    Available,
    /// The domain is already registered.
    Registered,
    /// Could not be determined (e.g. no registry service, or ambiguous WHOIS).
    #[default]
    Unknown,
}

/// Registration data for a domain, as much as the backend could resolve.
#[derive(Debug, Clone, Default, Serialize)]
pub struct DomainInfo {
    pub domain: String,
    pub availability: Availability,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registrar: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registered: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub nameservers: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub statuses: Vec<String>,
    /// Name of the backend that produced this result.
    pub source: &'static str,
}

/// A selected backend instance.
pub enum Backend {
    Auto(AutoBackend),
    Rdap(RdapBackend),
    Whois(WhoisBackend),
}

impl Backend {
    /// Resolve a backend by its CLI name (case-insensitive).
    pub fn from_name(name: &str) -> Result<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Backend::Auto(AutoBackend::new())),
            "rdap" => Ok(Backend::Rdap(RdapBackend::new())),
            "whois" => Ok(Backend::Whois(WhoisBackend::new())),
            other => {
                let names: Vec<&str> = BACKENDS.iter().map(|b| b.name).collect();
                bail!(
                    "unknown backend `{other}` (available: {})",
                    names.join(", ")
                )
            }
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Backend::Auto(_) => "auto",
            Backend::Rdap(_) => "rdap",
            Backend::Whois(_) => "whois",
        }
    }

    pub fn supports_whois(&self) -> bool {
        match self {
            Backend::Auto(_) | Backend::Rdap(_) | Backend::Whois(_) => true,
        }
    }

    /// Resolve availability and (where supported) registration data.
    pub async fn lookup(&self, domain: &str) -> Result<DomainInfo> {
        match self {
            Backend::Auto(b) => b.lookup(domain).await,
            Backend::Rdap(b) => b.lookup(domain).await,
            Backend::Whois(b) => b.lookup(domain).await,
        }
    }
}

/// Normalize user input into a bare lowercase domain with at least one dot.
/// Tolerates pasted URLs (`https://example.com/path` → `example.com`).
pub fn normalize_domain(input: &str) -> Result<String> {
    let mut d = input.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Some((_, rest)) = d.split_once("://") {
        d = rest.to_string();
    }
    if let Some((host, _)) = d.split_once('/') {
        d = host.to_string();
    }
    if d.is_empty() || !d.contains('.') || d.starts_with('.') {
        bail!("`{input}` is not a valid domain (expected something like `example.com`)");
    }
    Ok(d)
}

/// The TLD (last label) of an already-normalized domain.
pub fn tld_of(domain: &str) -> &str {
    domain.rsplit('.').next().unwrap_or(domain)
}
