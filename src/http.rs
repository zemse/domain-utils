//! HTTP reachability: redirect chain, final status, and security headers.
//!
//! Follows redirects manually (rather than letting the client auto-follow) so
//! the full hop-by-hop chain is visible, then reports the final response's
//! status and a few security-relevant headers — notably HSTS
//! (`Strict-Transport-Security`).

use anyhow::{Context, Result, anyhow, bail};
use reqwest::{Url, redirect::Policy};
use serde::Serialize;

/// Maximum redirects to follow before giving up (guards against loops).
const MAX_HOPS: usize = 10;
const TIMEOUT_SECS: u64 = 15;

#[derive(Debug, Serialize)]
pub struct HttpInfo {
    pub url: String,
    pub hops: Vec<Hop>,
    pub final_status: u16,
    pub final_url: String,
    /// `Strict-Transport-Security` header value on the final response, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hsts: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Hop {
    pub url: String,
    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
}

/// Trace the redirect chain for `target`, returning the chain and final headers.
///
/// A bare host (`example.com`) is assumed to be `https://example.com`.
pub async fn inspect(target: &str) -> Result<HttpInfo> {
    let start = normalize_url(target)?;
    let client = reqwest::Client::builder()
        .user_agent(concat!(
            env!("CARGO_PKG_NAME"),
            "/",
            env!("CARGO_PKG_VERSION")
        ))
        // Follow redirects ourselves so each hop is recorded.
        .redirect(Policy::none())
        .timeout(std::time::Duration::from_secs(TIMEOUT_SECS))
        .build()
        .context("building HTTP client")?;

    let mut hops = Vec::new();
    let mut current = start.clone();
    for _ in 0..=MAX_HOPS {
        let resp = client
            .get(current.clone())
            .send()
            .await
            .with_context(|| format!("requesting {current}"))?;
        let status = resp.status();
        let location = resp
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);

        hops.push(Hop {
            url: current.to_string(),
            status: status.as_u16(),
            location: location.clone(),
        });

        // Not a redirect (or no Location to follow) → this is the final response.
        if !status.is_redirection() || location.is_none() {
            let hsts = header(&resp, "strict-transport-security");
            let server = header(&resp, "server");
            return Ok(HttpInfo {
                url: start.to_string(),
                final_status: status.as_u16(),
                final_url: current.to_string(),
                hops,
                hsts,
                server,
            });
        }

        let location = location.expect("checked is_some above");
        // Location may be relative; resolve it against the current URL.
        current = current
            .join(&location)
            .with_context(|| format!("resolving redirect target `{location}`"))?;
    }

    bail!("too many redirects (>{MAX_HOPS}) starting from {start}")
}

/// Read a response header as an owned string, if present and valid UTF-8.
fn header(resp: &reqwest::Response, name: &str) -> Option<String> {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// Parse `target` into a URL, defaulting a scheme-less host to `https://`.
fn normalize_url(target: &str) -> Result<Url> {
    let target = target.trim();
    if target.is_empty() {
        bail!("empty URL");
    }
    let with_scheme = if target.contains("://") {
        target.to_string()
    } else {
        format!("https://{target}")
    };
    Url::parse(&with_scheme).map_err(|e| anyhow!("`{target}` is not a valid URL: {e}"))
}
