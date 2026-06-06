//! Domain registration pricing via Porkbun's public, keyless pricing endpoint.
//!
//! `https://api.porkbun.com/api/json/v3/pricing/get` returns Porkbun's
//! registration/renewal/transfer prices (USD) for ~900 TLDs with no API key.
//! These are Porkbun's retail prices — indicative, not a market minimum.

use std::collections::HashMap;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

const PRICING_URL: &str = "https://api.porkbun.com/api/json/v3/pricing/get";

/// Per-TLD prices (USD). Unknown fields in the response (e.g. coupons) are ignored.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TldPrice {
    pub registration: String,
    pub renewal: String,
    pub transfer: String,
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
    pub async fn fetch_all(&self) -> Result<HashMap<String, TldPrice>> {
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
