mod backend;
mod cli;
mod dns;
mod output;

use std::collections::HashSet;
use std::io::{IsTerminal, Read};
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use tokio::sync::Semaphore;

use crate::backend::{Backend, DomainInfo};
use crate::cli::{BatchInput, Cli, Command, DnsArgs, LookupArgs};
use crate::dns::{DEFAULT_TYPES, DnsClient, DnsRecord};

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

#[derive(Clone, Copy)]
enum Mode {
    Check,
    Whois,
}

async fn run(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        Command::Backends => {
            output::print_backends();
            Ok(ExitCode::SUCCESS)
        }
        Command::Check(args) => run_lookups(args, Mode::Check).await,
        Command::Whois(args) => run_lookups(args, Mode::Whois).await,
        Command::Dns(args) => run_dns(args).await,
        Command::Ns(input) => {
            run_dns(DnsArgs {
                input,
                types: vec!["NS".to_string()],
            })
            .await
        }
    }
}

async fn run_lookups(args: LookupArgs, mode: Mode) -> Result<ExitCode> {
    let backend = Backend::from_name(&args.backend)?;
    if matches!(mode, Mode::Whois) && !backend.supports_whois() {
        bail!(
            "backend `{}` does not support whois lookups; try `--backend rdap`",
            backend.name()
        );
    }
    let backend_name = backend.name();
    let domains = gather_domains(&args.input)?;

    let results = lookup_all(Arc::new(backend), &domains, args.input.concurrency).await;

    // Print in input order; tally a summary for multi-domain runs.
    let mut summary = output::Summary::default();
    for (domain, result) in &results {
        match result {
            Ok(info) => {
                match mode {
                    Mode::Check => output::print_check(info),
                    Mode::Whois => output::print_whois(info),
                }
                summary.record_ok(info.availability);
            }
            Err(e) => {
                output::print_lookup_error(domain, backend_name, e);
                summary.record_err();
            }
        }
    }
    if domains.len() > 1 {
        output::print_summary(&summary);
    }

    Ok(if summary.errors > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

async fn run_dns(args: DnsArgs) -> Result<ExitCode> {
    let domains = gather_domains(&args.input)?;
    let types: Vec<String> = if args.types.is_empty() {
        DEFAULT_TYPES.iter().map(|t| t.to_string()).collect()
    } else {
        args.types.iter().map(|t| t.to_ascii_uppercase()).collect()
    };

    let results = resolve_all(
        Arc::new(DnsClient::new()),
        &domains,
        &types,
        args.input.concurrency,
    )
    .await;

    let mut any_error = false;
    for (domain, per_type) in &results {
        for (_, r) in per_type {
            if r.is_err() {
                any_error = true;
            }
        }
        output::print_dns(domain, per_type);
    }

    Ok(if any_error {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

/// Resolve every (domain, type) pair concurrently (bounded by `concurrency`),
/// returning, per domain in input order, the records for each type in order.
#[allow(clippy::type_complexity)]
async fn resolve_all(
    client: Arc<DnsClient>,
    domains: &[String],
    types: &[String],
    concurrency: usize,
) -> Vec<(String, Vec<(String, Result<Vec<DnsRecord>>)>)> {
    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut set = tokio::task::JoinSet::new();
    for (di, domain) in domains.iter().cloned().enumerate() {
        for (ti, rtype) in types.iter().cloned().enumerate() {
            let client = Arc::clone(&client);
            let sem = Arc::clone(&sem);
            let domain = domain.clone();
            set.spawn(async move {
                let _permit = sem.acquire_owned().await.expect("semaphore is not closed");
                let result = client.lookup(&domain, &rtype).await;
                (di, ti, rtype, result)
            });
        }
    }

    // grid[di][ti] = (type, result)
    let mut grid: Vec<Vec<Option<(String, Result<Vec<DnsRecord>>)>>> = domains
        .iter()
        .map(|_| (0..types.len()).map(|_| None).collect())
        .collect();
    while let Some(joined) = set.join_next().await {
        if let Ok((di, ti, rtype, result)) = joined {
            grid[di][ti] = Some((rtype, result));
        }
    }

    domains
        .iter()
        .cloned()
        .zip(grid)
        .map(|(domain, row)| {
            let per_type = row
                .into_iter()
                .enumerate()
                .map(|(ti, slot)| {
                    slot.unwrap_or_else(|| (types[ti].clone(), Err(anyhow!("DNS task failed"))))
                })
                .collect();
            (domain, per_type)
        })
        .collect()
}

/// Look up every domain concurrently (bounded by `concurrency`), returning
/// results in the original input order.
async fn lookup_all(
    backend: Arc<Backend>,
    domains: &[String],
    concurrency: usize,
) -> Vec<(String, Result<DomainInfo>)> {
    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut set = tokio::task::JoinSet::new();
    for (index, domain) in domains.iter().cloned().enumerate() {
        let backend = Arc::clone(&backend);
        let sem = Arc::clone(&sem);
        set.spawn(async move {
            // Permit is held until the lookup completes, then released.
            let _permit = sem.acquire_owned().await.expect("semaphore is not closed");
            let result = backend.lookup(&domain).await;
            (index, domain, result)
        });
    }

    let mut slots: Vec<Option<(String, Result<DomainInfo>)>> =
        (0..domains.len()).map(|_| None).collect();
    while let Some(joined) = set.join_next().await {
        if let Ok((index, domain, result)) = joined {
            slots[index] = Some((domain, result));
        }
        // A JoinError means the task panicked; that slot stays None and is
        // filled with a generic error below.
    }

    slots
        .into_iter()
        .enumerate()
        .map(|(i, slot)| {
            slot.unwrap_or_else(|| (domains[i].clone(), Err(anyhow!("lookup task failed"))))
        })
        .collect()
}

/// Collect domains from positional args, `--file`, and/or piped stdin, then
/// de-duplicate while preserving first-seen order.
fn gather_domains(input: &BatchInput) -> Result<Vec<String>> {
    let mut raw: Vec<String> = input.domains.clone();

    if let Some(path) = &input.file {
        let text = if path.as_os_str() == "-" {
            read_stdin().context("reading domains from stdin (--file -)")?
        } else {
            std::fs::read_to_string(path)
                .with_context(|| format!("reading domains from {}", path.display()))?
        };
        raw.extend(parse_domain_list(&text));
    }

    // If no domains were supplied and stdin is piped, read the list from it.
    if raw.is_empty() && !std::io::stdin().is_terminal() {
        let text = read_stdin().context("reading domains from stdin")?;
        raw.extend(parse_domain_list(&text));
    }

    if raw.is_empty() {
        bail!("no domains given; pass them as arguments, via --file, or on stdin");
    }

    let mut seen = HashSet::new();
    Ok(raw.into_iter().filter(|d| seen.insert(d.clone())).collect())
}

fn read_stdin() -> std::io::Result<String> {
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf)?;
    Ok(buf)
}

/// Split a text blob into domains: whitespace-separated, `#` starts a comment.
fn parse_domain_list(text: &str) -> Vec<String> {
    text.lines()
        .map(|line| line.split('#').next().unwrap_or("").trim())
        .flat_map(str::split_whitespace)
        .map(str::to_string)
        .collect()
}
