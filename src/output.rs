//! Human-friendly terminal output. Colors are emitted only when stdout is a
//! TTY and `NO_COLOR` is unset.

use std::io::IsTerminal;
use std::sync::OnceLock;

use crate::backend::{Availability, BACKENDS, DomainInfo};
use crate::dns::DnsRecord;
use crate::email::EmailInfo;
use crate::tls::TlsInfo;

fn color_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED
        .get_or_init(|| std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal())
}

fn paint(code: &str, text: &str) -> String {
    if color_enabled() {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

fn green(t: &str) -> String {
    paint("32", t)
}
fn yellow(t: &str) -> String {
    paint("33", t)
}
fn red(t: &str) -> String {
    paint("31", t)
}
fn dim(t: &str) -> String {
    paint("2", t)
}
fn bold(t: &str) -> String {
    paint("1", t)
}

/// One-line availability result for `domain check`.
pub fn print_check(info: &DomainInfo) {
    match info.availability {
        Availability::Available => {
            println!(
                "{} {}  {}",
                green("✓"),
                bold(&info.domain),
                green("available")
            );
        }
        Availability::Registered => {
            let suffix = match &info.registrar {
                Some(r) => format!("  {}", dim(&format!("({r})"))),
                None => String::new(),
            };
            println!(
                "{} {}  {}{}",
                red("✗"),
                bold(&info.domain),
                yellow("registered"),
                suffix
            );
        }
        Availability::Unknown => {
            println!("{} {}  {}", dim("?"), bold(&info.domain), dim("unknown"));
        }
    }
}

/// Detailed registration record for `domain whois`.
pub fn print_whois(info: &DomainInfo) {
    println!("{}", bold(&info.domain));
    let status = match info.availability {
        Availability::Available => green("available (not registered)"),
        Availability::Registered => yellow("registered"),
        Availability::Unknown => dim("unknown"),
    };
    field("status", &status);
    if let Some(r) = &info.registrar {
        field("registrar", r);
    }
    if let Some(d) = &info.registered {
        field("registered", d);
    }
    if let Some(d) = &info.expires {
        field("expires", d);
    }
    if let Some(d) = &info.updated {
        field("updated", d);
    }
    if !info.nameservers.is_empty() {
        field("nameservers", &info.nameservers.join(", "));
    }
    if !info.statuses.is_empty() {
        field("epp status", &info.statuses.join(", "));
    }
    field("source", info.source);
    println!();
}

fn field(label: &str, value: &str) {
    println!("  {:<13} {}", dim(&format!("{label}:")), value);
}

/// `domain backends` — list backends and their key requirements.
pub fn print_backends() {
    println!("{}", bold("Available backends:"));
    for b in BACKENDS {
        let key = if b.requires_api_key {
            yellow("needs API key")
        } else {
            green("keyless")
        };
        let whois = if b.supports_whois {
            "whois ✓"
        } else {
            "whois ✗"
        };
        println!(
            "  {:<8} [{}, {}]  {}",
            bold(b.name),
            key,
            dim(whois),
            b.blurb
        );
    }
}

/// Error for a single domain lookup, with a hint about other backends.
pub fn print_lookup_error(domain: &str, backend: &str, err: &anyhow::Error) {
    eprintln!(
        "{} {}  {}",
        red("!"),
        bold(domain),
        dim(&format!("[{backend}] {err:#}"))
    );
}

/// DNS records for one domain, grouped by the queried record type.
pub fn print_dns(domain: &str, per_type: &[(String, anyhow::Result<Vec<DnsRecord>>)]) {
    println!("{}", bold(domain));
    for (rtype, result) in per_type {
        match result {
            Ok(records) if records.is_empty() => {
                println!("  {:<6} {}", dim(rtype), dim("(none)"));
            }
            Ok(records) => {
                for rec in records {
                    // A record's own type can differ from the query (e.g. a
                    // CNAME returned when asking for A); show the actual type.
                    let label = if &rec.record_type == rtype {
                        rtype.clone()
                    } else {
                        format!("{rtype}→{}", rec.record_type)
                    };
                    println!(
                        "  {:<6} {}  {}",
                        green(&label),
                        rec.value,
                        dim(&format!("ttl {}", rec.ttl))
                    );
                }
            }
            Err(e) => {
                println!("  {:<6} {}", red(rtype), dim(&format!("error: {e:#}")));
            }
        }
    }
    println!();
}

/// Email-security posture for one domain (`domain email`).
pub fn print_email(info: &EmailInfo) {
    println!("{}", bold(&info.domain));

    // MX
    if info.mx.is_empty() {
        println!("  {} {}  {}", red("✗"), pad("MX"), dim("no MX records"));
    } else {
        println!(
            "  {} {}  {} record(s)",
            green("✓"),
            pad("MX"),
            info.mx.len()
        );
        for mx in &info.mx {
            println!("           {}", dim(mx));
        }
    }

    // SPF
    match &info.spf {
        Some(record) => {
            let policy = info
                .spf_policy
                .as_deref()
                .map(|p| format!("  {}", dim(&format!("({p})"))))
                .unwrap_or_default();
            println!("  {} {}  {}{}", green("✓"), pad("SPF"), record, policy);
        }
        None => println!("  {} {}  {}", red("✗"), pad("SPF"), dim("no SPF record")),
    }

    // DMARC
    match &info.dmarc {
        Some(_) => {
            let policy = info.dmarc_policy.as_deref().unwrap_or("(no p= tag)");
            let warn = if info.dmarc_policy.as_deref() == Some("none") {
                format!("  {}", dim("(monitoring only)"))
            } else {
                String::new()
            };
            println!("  {} {}  p={}{}", green("✓"), pad("DMARC"), policy, warn);
        }
        None => println!(
            "  {} {}  {}",
            red("✗"),
            pad("DMARC"),
            dim("no DMARC record")
        ),
    }

    // DKIM
    if info.dkim_selectors.is_empty() {
        println!(
            "  {} {}  {}",
            yellow("?"),
            pad("DKIM"),
            dim("no common selector found (DKIM may use a custom selector)")
        );
    } else {
        println!(
            "  {} {}  selectors: {}",
            green("✓"),
            pad("DKIM"),
            info.dkim_selectors.join(", ")
        );
    }
    println!();
}

/// Pad a short record-type label to a fixed width (color-safe — no color here).
fn pad(label: &str) -> String {
    format!("{label:<6}")
}

/// TLS certificate summary for one domain (`domain tls`).
pub fn print_tls(info: &TlsInfo) {
    println!("{}", bold(&format!("{}:{}", info.domain, info.port)));
    if let Some(s) = &info.subject {
        field("subject", s);
    }
    if let Some(i) = &info.issuer {
        field("issuer", i);
    }
    field("not before", &info.not_before);
    field("not after", &info.not_after);

    // Highlight the expiry: red if expired, yellow if within 30 days.
    let expiry = if info.expired {
        red("EXPIRED")
    } else if info.days_to_expiry <= 30 {
        yellow(&format!("{} days left", info.days_to_expiry))
    } else {
        green(&format!("{} days left", info.days_to_expiry))
    };
    field("expiry", &expiry);

    if !info.san.is_empty() {
        // Cap the SAN list so a wildcard cert with hundreds of names stays readable.
        let shown = 8;
        let mut sans = info
            .san
            .iter()
            .take(shown)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        if info.san.len() > shown {
            sans.push_str(&dim(&format!(" (+{} more)", info.san.len() - shown)));
        }
        field("SANs", &sans);
    }
    println!();
}

/// Running tally of a batch run, printed as a summary line at the end.
#[derive(Default)]
pub struct Summary {
    pub available: usize,
    pub registered: usize,
    pub unknown: usize,
    pub errors: usize,
}

impl Summary {
    pub fn record_ok(&mut self, availability: Availability) {
        match availability {
            Availability::Available => self.available += 1,
            Availability::Registered => self.registered += 1,
            Availability::Unknown => self.unknown += 1,
        }
    }

    pub fn record_err(&mut self) {
        self.errors += 1;
    }
}

/// One-line tally for a multi-domain batch, e.g. `2 available · 3 registered · 1 error`.
pub fn print_summary(s: &Summary) {
    let mut parts = Vec::new();
    if s.available > 0 {
        parts.push(green(&format!("{} available", s.available)));
    }
    if s.registered > 0 {
        parts.push(yellow(&format!("{} registered", s.registered)));
    }
    if s.unknown > 0 {
        parts.push(dim(&format!("{} unknown", s.unknown)));
    }
    if s.errors > 0 {
        parts.push(red(&format!("{} error{}", s.errors, plural(s.errors))));
    }
    if parts.is_empty() {
        return;
    }
    println!("{} {}", dim("—"), parts.join(&dim(" · ")));
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}
