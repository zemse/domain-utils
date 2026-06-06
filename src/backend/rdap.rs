//! Keyless RDAP backend.
//!
//! Availability is resolved by mapping the domain's TLD to its registry RDAP
//! server via the IANA bootstrap registry (`https://data.iana.org/rdap/dns.json`)
//! and querying that server directly. This is the keyless, no-shared-rate-limit
//! path, and — crucially — it avoids the classic false-positive bug: a bare
//! `404` is only treated as "available" once we've confirmed the TLD actually
//! has an RDAP service. TLDs with no RDAP service (e.g. `.de`, `.io`, `.co`,
//! `.me`, `.us`) resolve to [`Availability::Unknown`] rather than a wrong
//! "available", and the caller is told to try another backend.

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;
use tokio::sync::OnceCell;

use super::{Availability, DomainInfo};

const BOOTSTRAP_URL: &str = "https://data.iana.org/rdap/dns.json";

pub struct RdapBackend {
    client: reqwest::Client,
    /// Cached IANA bootstrap document, fetched once per process and reused
    /// across multiple domain lookups.
    bootstrap: OnceCell<Value>,
}

impl RdapBackend {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .user_agent(concat!("domain-cli/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("failed to build HTTP client");
        Self {
            client,
            bootstrap: OnceCell::new(),
        }
    }

    pub async fn lookup(&self, domain: &str) -> Result<DomainInfo> {
        let domain = normalize_domain(domain)?;
        let tld = domain
            .rsplit('.')
            .next()
            .expect("normalized domain has a dot");

        let base = self.rdap_base_for_tld(tld).await?.ok_or_else(|| {
            anyhow!(
                "`.{tld}` has no RDAP service in the IANA registry, \
                 so availability can't be determined via the `rdap` backend; \
                 try another backend (e.g. a port-43 WHOIS fallback) once available"
            )
        })?;

        let url = format!("{}/domain/{}", base.trim_end_matches('/'), domain);
        let resp = self
            .client
            .get(&url)
            .header("Accept", "application/rdap+json")
            .send()
            .await
            .with_context(|| format!("requesting {url}"))?;

        match resp.status().as_u16() {
            // Registry has a record → registered. Parse what we can.
            200 => {
                let body: Value = resp
                    .json()
                    .await
                    .with_context(|| format!("parsing RDAP response from {url}"))?;
                Ok(parse_registered(domain, &body))
            }
            // Confirmed RDAP service for this TLD returned "not found" → available.
            404 => Ok(DomainInfo {
                domain,
                availability: Availability::Available,
                source: "rdap",
                ..Default::default()
            }),
            429 => bail!("RDAP server rate-limited the request (HTTP 429): {url}"),
            other => bail!("RDAP server returned HTTP {other}: {url}"),
        }
    }

    /// Look up the registry RDAP base URL for a TLD via the cached bootstrap.
    async fn rdap_base_for_tld(&self, tld: &str) -> Result<Option<String>> {
        let bootstrap = self.bootstrap().await?;
        Ok(find_rdap_base(bootstrap, tld))
    }

    async fn bootstrap(&self) -> Result<&Value> {
        self.bootstrap
            .get_or_try_init(|| async {
                let resp = self
                    .client
                    .get(BOOTSTRAP_URL)
                    .send()
                    .await
                    .with_context(|| format!("fetching IANA RDAP bootstrap from {BOOTSTRAP_URL}"))?
                    .error_for_status()
                    .context("IANA RDAP bootstrap returned an error status")?;
                let json = resp
                    .json::<Value>()
                    .await
                    .context("parsing IANA RDAP bootstrap JSON")?;
                Ok::<_, anyhow::Error>(json)
            })
            .await
    }
}

/// Normalize user input into a bare lowercase domain with at least one dot.
fn normalize_domain(input: &str) -> Result<String> {
    let mut d = input.trim().trim_end_matches('.').to_ascii_lowercase();
    // Strip a scheme/path if the user pasted a URL.
    if let Some(rest) = d.split_once("://") {
        d = rest.1.to_string();
    }
    if let Some((host, _)) = d.split_once('/') {
        d = host.to_string();
    }
    if d.is_empty() || !d.contains('.') || d.starts_with('.') {
        bail!("`{input}` is not a valid domain (expected something like `example.com`)");
    }
    Ok(d)
}

/// Find the registry RDAP base URL for a TLD in the IANA bootstrap document.
///
/// `services` is an array of `[[tld, ...], [base_url, ...]]` pairs.
fn find_rdap_base(bootstrap: &Value, tld: &str) -> Option<String> {
    let services = bootstrap.get("services")?.as_array()?;
    for service in services {
        let Some(pair) = service.as_array() else {
            continue;
        };
        let (Some(tlds), Some(urls)) = (
            pair.first().and_then(Value::as_array),
            pair.get(1).and_then(Value::as_array),
        ) else {
            continue;
        };
        let matches = tlds
            .iter()
            .filter_map(Value::as_str)
            .any(|t| t.eq_ignore_ascii_case(tld));
        if matches {
            // Prefer an https base URL if present, else the first one.
            let https = urls
                .iter()
                .filter_map(Value::as_str)
                .find(|u| u.starts_with("https://"));
            return https
                .or_else(|| urls.iter().filter_map(Value::as_str).next())
                .map(str::to_string);
        }
    }
    None
}

/// Build a [`DomainInfo`] for a registered domain from its RDAP JSON body.
fn parse_registered(domain: String, body: &Value) -> DomainInfo {
    DomainInfo {
        domain,
        availability: Availability::Registered,
        registrar: registrar_name(body),
        registered: event_date(body, "registration"),
        expires: event_date(body, "expiration"),
        updated: event_date(body, "last changed"),
        nameservers: nameservers(body),
        statuses: statuses(body),
        source: "rdap",
    }
}

/// Find an `events[]` entry by `eventAction` and return its `eventDate`.
fn event_date(body: &Value, action: &str) -> Option<String> {
    body.get("events")?.as_array()?.iter().find_map(|e| {
        if e.get("eventAction")?.as_str()? == action {
            Some(e.get("eventDate")?.as_str()?.to_string())
        } else {
            None
        }
    })
}

/// Pull the registrar's display name out of the `entities[]` vCard.
fn registrar_name(body: &Value) -> Option<String> {
    let entities = body.get("entities")?.as_array()?;
    for entity in entities {
        let is_registrar = entity
            .get("roles")
            .and_then(Value::as_array)
            .map(|roles| {
                roles
                    .iter()
                    .filter_map(Value::as_str)
                    .any(|r| r == "registrar")
            })
            .unwrap_or(false);
        if !is_registrar {
            continue;
        }
        if let Some(name) = vcard_fn(entity.get("vcardArray")) {
            return Some(name);
        }
    }
    None
}

/// Extract the `fn` (formatted name) field from a jCard / vcardArray:
/// `["vcard", [ ["version",{},"text","4.0"], ["fn",{},"text","Registrar"], ... ]]`.
fn vcard_fn(vcard: Option<&Value>) -> Option<String> {
    let props = vcard?.as_array()?.get(1)?.as_array()?;
    for prop in props {
        let Some(prop) = prop.as_array() else {
            continue;
        };
        if prop.first().and_then(Value::as_str) == Some("fn")
            && let Some(name) = prop.get(3).and_then(Value::as_str)
        {
            return Some(name.to_string());
        }
    }
    None
}

fn nameservers(body: &Value) -> Vec<String> {
    body.get("nameservers")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|ns| ns.get("ldhName").and_then(Value::as_str))
                .map(|s| s.to_ascii_lowercase())
                .collect()
        })
        .unwrap_or_default()
}

fn statuses(body: &Value) -> Vec<String> {
    body.get("status")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}
