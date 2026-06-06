use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use clap_complete::Shell;

/// Domain toolkit: availability, WHOIS/RDAP registration data, and DNS records.
///
/// Run `domain <name>` for a quick lookup — it checks availability and, for any
/// name that's registered, also prints its full WHOIS/registration record. Or
/// use a subcommand for WHOIS-only, DNS, email, TLS, pricing, and more.
///
/// Availability/WHOIS use the keyless `auto` backend (RDAP→WHOIS) by default;
/// pick another with `--backend`. DNS lookups use DNS-over-HTTPS (keyless).
#[derive(Parser, Debug)]
#[command(name = "domain", version, about, long_about = None)]
#[command(args_conflicts_with_subcommands = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Domain(s) to look up when no subcommand is given (availability, plus
    /// WHOIS for any that are registered). Accepts the same options as `check`.
    #[command(flatten)]
    pub default: LookupArgs,

    /// Emit machine-readable JSON instead of the human-friendly output.
    #[arg(long, global = true)]
    pub json: bool,
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

    /// Inspect email-security records: MX, SPF, DMARC, DKIM.
    Email(BatchInput),

    /// Inspect a domain's live TLS certificate (issuer, SANs, expiry).
    Tls(TlsArgs),

    /// Reverse-DNS lookup: the PTR (hostname) for one or more IP addresses.
    Ptr(BatchInput),

    /// Show a domain's DNSSEC status (DS / DNSKEY records, validation).
    Dnssec(BatchInput),

    /// Trace a URL's redirect chain and report final status + HSTS header.
    Http(BatchInput),

    /// Compare a DNS record across public resolvers (propagation diff).
    Propagation(PropagationArgs),

    /// Show registration pricing for TLDs (via Porkbun, keyless).
    Price(PriceArgs),

    /// List TLD categories, or the TLDs within one. Use `all` for every TLD.
    Tlds {
        /// Category name (e.g. `finance`). Omit to list all categories.
        #[arg(value_name = "CATEGORY")]
        category: Option<String>,
    },

    /// List the available backends and whether each needs an API key.
    Backends,

    /// Generate a shell completion script (write it to stdout).
    Completions {
        /// Shell to generate completions for: bash, zsh, fish, powershell, elvish.
        #[arg(value_name = "SHELL")]
        shell: Shell,
    },
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

    /// Spray each name across these TLDs (comma-separated or repeated), e.g.
    /// `--tlds com,io,dev`. The name's own TLD (if any) is ignored.
    #[arg(long, value_name = "TLD", value_delimiter = ',')]
    pub tlds: Vec<String>,

    /// Spray across all TLDs in these categories, e.g. `--category finance,tech`.
    /// See `domain tlds` for the list.
    #[arg(
        short = 'C',
        long = "category",
        value_name = "CAT",
        value_delimiter = ','
    )]
    pub categories: Vec<String>,

    /// Spray across every known TLD (~1400). Slow and prone to rate limits.
    #[arg(long)]
    pub all_tlds: bool,

    /// Also show registration price (Porkbun, keyless) next to available results.
    #[arg(long)]
    pub price: bool,

    /// (whois only) Keep only domains expiring within this window, soonest first,
    /// e.g. `30d`, `6w`, `3m`, `1y` (a bare number means days).
    #[arg(long, value_name = "DURATION")]
    pub expiring_within: Option<String>,
}

/// Arguments for `price`.
#[derive(Args, Debug)]
pub struct PriceArgs {
    /// TLDs or domains to price (the TLD is used), e.g. `com io example.dev`.
    #[arg(value_name = "TLD|DOMAIN")]
    pub items: Vec<String>,

    /// Include all TLDs in these categories. See `domain tlds`.
    #[arg(
        short = 'C',
        long = "category",
        value_name = "CAT",
        value_delimiter = ','
    )]
    pub categories: Vec<String>,

    /// Price every TLD Porkbun offers.
    #[arg(long)]
    pub all: bool,
}

/// Arguments for `tls`.
#[derive(Args, Debug)]
pub struct TlsArgs {
    #[command(flatten)]
    pub input: BatchInput,

    /// Port to connect to for the TLS handshake.
    #[arg(short, long, default_value_t = 443, value_name = "PORT")]
    pub port: u16,
}

/// Arguments for `propagation`.
#[derive(Args, Debug)]
pub struct PropagationArgs {
    #[command(flatten)]
    pub input: BatchInput,

    /// Record type to compare across resolvers (default: A).
    #[arg(short = 't', long = "type", default_value = "A", value_name = "TYPE")]
    pub record_type: String,
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
