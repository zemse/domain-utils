//! Domain registration pricing via Porkbun's public, keyless pricing endpoint.
//!
//! `https://api.porkbun.com/api/json/v3/pricing/get` returns Porkbun's
//! registration/renewal/transfer prices (USD) for ~900 TLDs with no API key.
//! These are Porkbun's retail prices — indicative, not a market minimum.
//!
//! That endpoint is slow (~15s server-side, regardless of the ~80 KB payload),
//! and there's no per-TLD variant, so the full table is cached on disk with a
//! 24h TTL: the first `--pricing` run pays the latency once, later runs read the
//! local copy instantly.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

const PRICING_URL: &str = "https://api.porkbun.com/api/json/v3/pricing/get";

/// How long a cached pricing table stays fresh. Registry prices move on the
/// order of days, so a day-long cache keeps quotes current enough.
const CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// The pricing provider these quotes come from (shown next to prices and used as
/// the `source` field in JSON output).
pub const PROVIDER: &str = "porkbun";

/// Per-TLD prices (USD). Unknown fields in the response (e.g. coupons) are ignored.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TldPrice {
    pub registration: String,
    pub renewal: String,
    pub transfer: String,
}

/// On-disk cache wrapper: the pricing table plus the unix timestamp (seconds)
/// it was fetched at. Storing the timestamp in the file makes freshness
/// independent of the file's mtime (which backups, copies, and `touch` reset).
#[derive(Deserialize, Serialize)]
struct CacheFile {
    fetched_at: u64,
    pricing: HashMap<String, TldPrice>,
}

#[derive(Deserialize)]
struct PricingResponse {
    status: String,
    #[serde(default)]
    pricing: HashMap<String, TldPrice>,
}

pub struct PriceClient {
    client: reqwest::Client,
}

impl PriceClient {
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

    /// Fetch the full TLD → price map (keyed by lowercase TLD, no leading dot).
    ///
    /// Returns a fresh on-disk cache when one exists; otherwise hits the network
    /// and writes the result back to the cache. Cache I/O is best-effort — a
    /// failure to read or write it never fails the lookup.
    pub async fn fetch_all(&self) -> Result<HashMap<String, TldPrice>> {
        if let Some(cached) = read_cache() {
            return Ok(cached);
        }
        let map = self.fetch_remote().await?;
        write_cache(&map);
        Ok(map)
    }

    /// Hit Porkbun's pricing endpoint directly (no cache).
    async fn fetch_remote(&self) -> Result<HashMap<String, TldPrice>> {
        let resp = self
            .client
            .get(PRICING_URL)
            .send()
            .await
            .context("requesting Porkbun pricing")?
            .error_for_status()
            .context("Porkbun pricing returned an error status")?;
        let body: PricingResponse = resp.json().await.context("parsing Porkbun pricing JSON")?;
        if body.status != "SUCCESS" {
            bail!("Porkbun pricing returned status `{}`", body.status);
        }
        Ok(body.pricing)
    }
}

/// Path to the on-disk pricing cache, using the platform's cache directory:
/// `~/Library/Caches/domain-utils/` on macOS, `$XDG_CACHE_HOME` or `~/.cache/`
/// elsewhere. `None` if no home directory can be resolved.
fn cache_path() -> Option<PathBuf> {
    let base = if cfg!(target_os = "macos") {
        let mut p = PathBuf::from(std::env::var_os("HOME")?);
        p.push("Library/Caches");
        p
    } else if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME").filter(|v| !v.is_empty()) {
        PathBuf::from(xdg)
    } else {
        let mut p = PathBuf::from(std::env::var_os("HOME")?);
        p.push(".cache");
        p
    };
    Some(base.join("domain-utils").join("porkbun-pricing.json"))
}

/// Current unix time in whole seconds, or `None` if the clock is before the
/// epoch.
fn now_unix() -> Option<u64> {
    Some(SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs())
}

/// Read the cached pricing table if it exists and its stored `fetched_at` is
/// younger than `CACHE_TTL`. A missing, unreadable, malformed, or future-dated
/// (clock-skew) entry is treated as "no cache".
fn read_cache() -> Option<HashMap<String, TldPrice>> {
    let path = cache_path()?;
    let cache: CacheFile = serde_json::from_str(&std::fs::read_to_string(&path).ok()?).ok()?;
    let age = now_unix()?.checked_sub(cache.fetched_at)?;
    if age > CACHE_TTL.as_secs() {
        return None;
    }
    Some(cache.pricing)
}

/// Write the pricing table to the on-disk cache, stamped with the current time
/// (best-effort; errors ignored).
fn write_cache(map: &HashMap<String, TldPrice>) {
    let (Some(path), Some(fetched_at)) = (cache_path(), now_unix()) else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let cache = CacheFile {
        fetched_at,
        pricing: map.clone(),
    };
    if let Ok(text) = serde_json::to_string(&cache) {
        let _ = std::fs::write(&path, text);
    }
}
