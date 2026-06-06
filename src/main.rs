mod backend;
mod cli;
mod output;

use std::process::ExitCode;

use clap::Parser;

use crate::backend::Backend;
use crate::cli::{Cli, Command};

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    match cli.command {
        Command::Backends => {
            output::print_backends();
            Ok(ExitCode::SUCCESS)
        }
        Command::Check { domains, backend } => {
            let backend = Backend::from_name(&backend)?;
            let mut any_error = false;
            for domain in &domains {
                match backend.lookup(domain).await {
                    Ok(info) => output::print_check(&info),
                    Err(e) => {
                        any_error = true;
                        output::print_lookup_error(domain, backend.name(), &e);
                    }
                }
            }
            Ok(if any_error {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            })
        }
        Command::Whois { domains, backend } => {
            let backend = Backend::from_name(&backend)?;
            if !backend.supports_whois() {
                anyhow::bail!(
                    "backend `{}` does not support whois lookups; try `--backend rdap`",
                    backend.name()
                );
            }
            let mut any_error = false;
            for domain in &domains {
                match backend.lookup(domain).await {
                    Ok(info) => output::print_whois(&info),
                    Err(e) => {
                        any_error = true;
                        output::print_lookup_error(domain, backend.name(), &e);
                    }
                }
            }
            Ok(if any_error {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            })
        }
    }
}
