use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// Domain toolkit: availability, WHOIS/RDAP registration data, and DNS records.
///
/// Availability/WHOIS use the keyless `auto` backend (RDAP→WHOIS) by default;
/// pick another with `--backend`. DNS lookups use DNS-over-HTTPS (keyless).
#[derive(Parser, Debug)]
#[command(name = "domain", version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Check whether one or more domains are available for registration.
    Check(LookupArgs),

    /// Look up WHOIS / registration data (registrar, dates, nameservers) for a domain.
    Whois(LookupArgs),

    /// Look up live DNS records for a domain (A, AAAA, MX, NS, TXT, …).
    Dns(DnsArgs),

    /// Show a domain's nameservers (shortcut for `dns --type NS`).
    Ns(BatchInput),

    /// List the available backends and whether each needs an API key.
    Backends,
}

/// Domains to operate on — shared across subcommands.
///
/// Domains may be passed as arguments, read from a file with `--file`, and/or
/// piped on stdin — they are all merged and de-duplicated, then processed
/// concurrently (see `--concurrency`).
#[derive(Args, Debug)]
pub struct BatchInput {
    /// Domain name(s), e.g. `example.com`. If none are given and stdin is
    /// piped, domains are read from stdin instead.
    #[arg(value_name = "DOMAIN")]
    pub domains: Vec<String>,

    /// Maximum number of lookups to run concurrently.
    #[arg(short, long, default_value_t = 10, value_name = "N")]
    pub concurrency: usize,

    /// Read additional domains from a file (one per line, whitespace-separated;
    /// `#` starts a comment). Use `-` to read the list from stdin.
    #[arg(short, long, value_name = "FILE")]
    pub file: Option<PathBuf>,
}

/// Arguments for `check` / `whois`.
#[derive(Args, Debug)]
pub struct LookupArgs {
    #[command(flatten)]
    pub input: BatchInput,

    /// Backend to use. Defaults to `auto` (RDAP→WHOIS, keyless). See `domain backends`.
    #[arg(short, long, default_value = "auto")]
    pub backend: String,
}

/// Arguments for `dns`.
#[derive(Args, Debug)]
pub struct DnsArgs {
    #[command(flatten)]
    pub input: BatchInput,

    /// Record type(s) to query (comma-separated or repeated). Default: A,AAAA,MX,NS,TXT.
    #[arg(short = 't', long = "type", value_name = "TYPE", value_delimiter = ',')]
    pub types: Vec<String>,
}
