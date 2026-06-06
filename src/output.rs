//! Human-friendly terminal output. Colors are emitted only when stdout is a
//! TTY and `NO_COLOR` is unset.

use std::io::IsTerminal;
use std::sync::OnceLock;

use crate::backend::{Availability, BACKENDS, DomainInfo};

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
