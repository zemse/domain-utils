use clap::{Parser, Subcommand};

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
    Check {
        /// Domain name(s) to check, e.g. `example.com`.
        #[arg(required = true, value_name = "DOMAIN")]
        domains: Vec<String>,

        /// Backend to use. Defaults to `rdap` (keyless). See `domain backends`.
        #[arg(short, long, default_value = "rdap")]
        backend: String,
    },

    /// Look up WHOIS / registration data (registrar, dates, nameservers) for a domain.
    Whois {
        /// Domain name(s) to look up, e.g. `example.com`.
        #[arg(required = true, value_name = "DOMAIN")]
        domains: Vec<String>,

        /// Backend to use. Defaults to `rdap` (keyless). See `domain backends`.
        #[arg(short, long, default_value = "rdap")]
        backend: String,
    },

    /// List the available backends and whether each needs an API key.
    Backends,
}
