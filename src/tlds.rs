//! Embedded TLD data: the full IANA TLD list plus a curated category map.
//!
//! Both data files are baked into the binary with `include_str!`, so TLD
//! lookups and category expansion need no network. The full list comes from
//! IANA (`data/tlds.txt`); categories are curated in `data/tld-categories.json`
//! and validated against that list by a test.

use std::collections::BTreeMap;
use std::sync::OnceLock;

const TLD_LIST: &str = include_str!("../data/tlds.txt");
const CATEGORIES_JSON: &str = include_str!("../data/tld-categories.json");

/// Every delegated TLD (lowercase), excluding comments. Parsed once.
pub fn all_tlds() -> &'static [&'static str] {
    static TLDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    TLDS.get_or_init(|| {
        let mut tlds: Vec<&'static str> = TLD_LIST
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();
        tlds.sort_unstable();
        tlds
    })
}

/// Curated category → TLDs map, sorted by category name. Parsed once.
pub fn categories() -> &'static BTreeMap<String, Vec<String>> {
    static CATEGORIES: OnceLock<BTreeMap<String, Vec<String>>> = OnceLock::new();
    CATEGORIES.get_or_init(|| {
        serde_json::from_str(CATEGORIES_JSON).expect("embedded tld-categories.json is valid")
    })
}

/// The TLDs in a category (case-insensitive name), if it exists.
pub fn category(name: &str) -> Option<&'static [String]> {
    let name = name.to_ascii_lowercase();
    categories().get(&name).map(Vec::as_slice)
}

/// All category names, sorted.
pub fn category_names() -> Vec<&'static str> {
    categories().keys().map(String::as_str).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn category_tlds_are_real_iana_delegations() {
        let valid: std::collections::HashSet<&str> = all_tlds().iter().copied().collect();
        let mut bad = Vec::new();
        for (cat, list) in categories() {
            for tld in list {
                if !valid.contains(tld.as_str()) {
                    bad.push(format!("{cat}:{tld}"));
                }
            }
        }
        assert!(
            bad.is_empty(),
            "categories reference undelegated TLDs: {bad:?}"
        );
    }

    #[test]
    fn all_tlds_is_sorted_for_binary_search() {
        let tlds = all_tlds();
        assert!(tlds.windows(2).all(|w| w[0] <= w[1]));
        assert!(tlds.len() > 1000, "expected the full IANA list");
    }
}
