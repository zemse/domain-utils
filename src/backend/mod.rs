//! Backends that resolve domain availability / registration data.
//!
//! Backends are dispatched through the [`Backend`] enum rather than a `dyn`
//! trait object so that adding a new backend is a single match arm and the
//! whole set is known at compile time. The default, [`rdap`], is keyless;
//! future backends (Porkbun, Route 53, a port-43 WHOIS fallback, …) may
//! require an API key — see [`Backend::requires_api_key`].

mod rdap;

use anyhow::Result;

use self::rdap::RdapBackend;

/// All backend names known to the CLI, in display order.
pub const BACKENDS: &[BackendInfo] = &[BackendInfo {
    name: "rdap",
    requires_api_key: false,
    supports_whois: true,
    blurb: "Keyless RDAP via the IANA bootstrap registry (default).",
}];

/// Static metadata about a backend, used by `domain backends`.
pub struct BackendInfo {
    pub name: &'static str,
    pub requires_api_key: bool,
    pub supports_whois: bool,
    pub blurb: &'static str,
}

/// Whether a domain is available, taken, or could not be determined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Availability {
    /// The registry has no record of the domain — it can be registered.
    Available,
    /// The domain is already registered.
    Registered,
    /// Could not be determined (e.g. the TLD has no RDAP service).
    #[default]
    Unknown,
}

/// Registration data for a domain, as much as the backend could resolve.
#[derive(Debug, Clone, Default)]
pub struct DomainInfo {
    pub domain: String,
    pub availability: Availability,
    pub registrar: Option<String>,
    pub registered: Option<String>,
    pub expires: Option<String>,
    pub updated: Option<String>,
    pub nameservers: Vec<String>,
    pub statuses: Vec<String>,
    /// Name of the backend that produced this result.
    pub source: &'static str,
}

/// A selected backend instance.
pub enum Backend {
    Rdap(RdapBackend),
}

impl Backend {
    /// Resolve a backend by its CLI name (case-insensitive).
    pub fn from_name(name: &str) -> Result<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "rdap" => Ok(Backend::Rdap(RdapBackend::new())),
            other => {
                let names: Vec<&str> = BACKENDS.iter().map(|b| b.name).collect();
                anyhow::bail!(
                    "unknown backend `{other}` (available: {})",
                    names.join(", ")
                )
            }
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Backend::Rdap(_) => "rdap",
        }
    }

    pub fn supports_whois(&self) -> bool {
        match self {
            Backend::Rdap(_) => true,
        }
    }

    /// Resolve availability and (where supported) registration data.
    pub async fn lookup(&self, domain: &str) -> Result<DomainInfo> {
        match self {
            Backend::Rdap(b) => b.lookup(domain).await,
        }
    }
}
