//! DNS propagation diff across public resolvers.
//!
//! Queries the same record on several public DoH resolvers (see
//! [`RESOLVERS`](crate::dns::RESOLVERS)) and compares the answers. When a record
//! has recently changed, resolvers can disagree until caches expire — this
//! surfaces that divergence.

use std::sync::Arc;

use anyhow::Result;
use serde::Serialize;
use tokio::sync::Semaphore;

use crate::dns::{DnsClient, RESOLVERS};

#[derive(Debug, Serialize)]
pub struct Propagation {
    pub domain: String,
    pub record_type: String,
    pub resolvers: Vec<ResolverResult>,
    /// True when every resolver that answered returned the same value set.
    pub consistent: bool,
}

#[derive(Debug, Serialize)]
pub struct ResolverResult {
    pub resolver: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Query `record_type` for `domain` on every resolver and diff the answers.
pub async fn check(client: &DnsClient, domain: &str, record_type: &str) -> Result<Propagation> {
    let sem = Arc::new(Semaphore::new(RESOLVERS.len()));
    let mut set = tokio::task::JoinSet::new();
    for (index, resolver) in RESOLVERS.iter().enumerate() {
        let client = client.clone();
        let sem = Arc::clone(&sem);
        let domain = domain.to_string();
        let record_type = record_type.to_string();
        set.spawn(async move {
            let _permit = sem.acquire_owned().await.expect("semaphore is not closed");
            let result = client.query(resolver.url, &domain, &record_type).await;
            (index, result)
        });
    }

    let mut slots: Vec<Option<ResolverResult>> = (0..RESOLVERS.len()).map(|_| None).collect();
    while let Some(joined) = set.join_next().await {
        if let Ok((index, result)) = joined {
            let name = RESOLVERS[index].name.to_string();
            slots[index] = Some(match result {
                Ok(answer) => {
                    // Keep only records of the queried type: some resolvers (e.g.
                    // dns.sb) also return RRSIG/DNSSEC records in the answer,
                    // which would otherwise look like spurious divergence.
                    let mut values: Vec<String> = answer
                        .records
                        .into_iter()
                        .filter(|r| r.record_type.eq_ignore_ascii_case(record_type))
                        .map(|r| r.value)
                        .collect();
                    values.sort();
                    ResolverResult {
                        resolver: name,
                        values,
                        error: None,
                    }
                }
                Err(e) => ResolverResult {
                    resolver: name,
                    values: Vec::new(),
                    error: Some(format!("{e:#}")),
                },
            });
        }
    }

    let resolvers: Vec<ResolverResult> = slots
        .into_iter()
        .enumerate()
        .map(|(i, slot)| {
            slot.unwrap_or_else(|| ResolverResult {
                resolver: RESOLVERS[i].name.to_string(),
                values: Vec::new(),
                error: Some("propagation task failed".to_string()),
            })
        })
        .collect();

    // Consistent iff every successful resolver returned the same value set.
    let answered: Vec<&Vec<String>> = resolvers
        .iter()
        .filter(|r| r.error.is_none())
        .map(|r| &r.values)
        .collect();
    let consistent = answered.windows(2).all(|w| w[0] == w[1]);

    Ok(Propagation {
        domain: domain.to_string(),
        record_type: record_type.to_string(),
        resolvers,
        consistent,
    })
}
