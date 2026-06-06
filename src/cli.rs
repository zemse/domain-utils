use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// Check domain availability and look up registration data across multiple backends.
///
/// The default backend is `rdap`, which is keyless and needs no signup. Other
/// backends (some requiring an API key) can be selected with `--backend`.
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

    /// List the available backends and whether each needs an API key.
    Backends,
}

/// Shared arguments for the `check` and `whois` subcommands.
///
/// Domains may be passed as arguments, read from a file with `--file`, and/or
/// piped on stdin — they are all merged and de-duplicated, then looked up
/// concurrently (see `--concurrency`).
#[derive(Args, Debug)]
pub struct LookupArgs {
    /// Domain name(s), e.g. `example.com`. If none are given and stdin is
    /// piped, domains are read from stdin instead.
    #[arg(value_name = "DOMAIN")]
    pub domains: Vec<String>,

    /// Backend to use. Defaults to `rdap` (keyless). See `domain backends`.
    #[arg(short, long, default_value = "rdap")]
    pub backend: String,

    /// Maximum number of lookups to run concurrently.
    #[arg(short, long, default_value_t = 10, value_name = "N")]
    pub concurrency: usize,

    /// Read additional domains from a file (one per line, whitespace-separated;
    /// `#` starts a comment). Use `-` to read the list from stdin.
    #[arg(short, long, value_name = "FILE")]
    pub file: Option<PathBuf>,
}
