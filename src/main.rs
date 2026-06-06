mod backend;
mod cli;
mod dns;
mod email;
mod output;
mod tlds;
mod tls;

use std::collections::HashSet;
use std::io::{IsTerminal, Read};
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use serde_json::{Value, json};
use tokio::sync::Semaphore;

use crate::backend::{Backend, DomainInfo};
use crate::cli::{BatchInput, Cli, Command, DnsArgs, LookupArgs, TlsArgs};
use crate::dns::{DEFAULT_TYPES, DnsClient, DnsRecord};
use crate::email::EmailInfo;
use crate::tls::TlsInfo;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let json = cli.json;
    match run(cli.command, json).await {
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

async fn run(command: Command, json: bool) -> Result<ExitCode> {
    match command {
        Command::Backends => {
            output::print_backends();
            Ok(ExitCode::SUCCESS)
        }
        Command::Tlds { category } => run_tlds(category, json),
        Command::Check(args) => run_lookups(args, Mode::Check, json).await,
        Command::Whois(args) => run_lookups(args, Mode::Whois, json).await,
        Command::Dns(args) => run_dns(args, json).await,
        Command::Ns(input) => {
            run_dns(
                DnsArgs {
                    input,
                    types: vec!["NS".to_string()],
                },
                json,
            )
            .await
        }
        Command::Email(input) => run_email(input, json).await,
        Command::Tls(args) => run_tls(args, json).await,
    }
}

async fn run_lookups(args: LookupArgs, mode: Mode, json: bool) -> Result<ExitCode> {
    let backend = Backend::from_name(&args.backend)?;
    if matches!(mode, Mode::Whois) && !backend.supports_whois() {
        bail!(
            "backend `{}` does not support whois lookups; try `--backend rdap`",
            backend.name()
        );
    }
    let backend_name = backend.name();
    let domains = expand_tlds(gather_domains(&args.input)?, &args)?;

    let results = lookup_all(Arc::new(backend), &domains, args.input.concurrency).await;
    let errors = results.iter().filter(|(_, r)| r.is_err()).count();

    if json {
        let arr: Vec<Value> = results
            .iter()
            .map(|(domain, result)| match result {
                Ok(info) => serde_json::to_value(info)
                    .unwrap_or_else(|_| json!({ "domain": domain, "error": "serialize failed" })),
                Err(e) => json!({ "domain": domain, "error": format!("{e:#}") }),
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&arr)?);
    } else {
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
    }

    Ok(exit_code(errors))
}

async fn run_dns(args: DnsArgs, json: bool) -> Result<ExitCode> {
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

    let mut errors = 0usize;
    if json {
        let arr: Vec<Value> = results
            .iter()
            .map(|(domain, per_type)| {
                let mut records = Vec::new();
                let mut errs = serde_json::Map::new();
                for (rtype, result) in per_type {
                    match result {
                        Ok(recs) => {
                            records.extend(recs.iter().filter_map(|r| serde_json::to_value(r).ok()))
                        }
                        Err(e) => {
                            errors += 1;
                            errs.insert(rtype.clone(), json!(format!("{e:#}")));
                        }
                    }
                }
                let mut obj = json!({ "domain": domain, "records": records });
                if !errs.is_empty() {
                    obj["errors"] = Value::Object(errs);
                }
                obj
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&arr)?);
    } else {
        for (domain, per_type) in &results {
            errors += per_type.iter().filter(|(_, r)| r.is_err()).count();
            output::print_dns(domain, per_type);
        }
    }

    Ok(exit_code(errors))
}

async fn run_email(input: BatchInput, json: bool) -> Result<ExitCode> {
    let concurrency = input.concurrency;
    let domains = gather_domains(&input)?;
    let results = email_all(Arc::new(DnsClient::new()), &domains, concurrency).await;
    let errors = results.iter().filter(|(_, r)| r.is_err()).count();

    if json {
        let arr: Vec<Value> = results
            .iter()
            .map(|(domain, result)| match result {
                Ok(info) => serde_json::to_value(info)
                    .unwrap_or_else(|_| json!({ "domain": domain, "error": "serialize failed" })),
                Err(e) => json!({ "domain": domain, "error": format!("{e:#}") }),
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&arr)?);
    } else {
        for (domain, result) in &results {
            match result {
                Ok(info) => output::print_email(info),
                Err(e) => output::print_lookup_error(domain, "email", e),
            }
        }
    }

    Ok(exit_code(errors))
}

/// Gather email-security records for every domain concurrently, in input order.
async fn email_all(
    client: Arc<DnsClient>,
    domains: &[String],
    concurrency: usize,
) -> Vec<(String, Result<EmailInfo>)> {
    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut set = tokio::task::JoinSet::new();
    for (index, domain) in domains.iter().cloned().enumerate() {
        let client = Arc::clone(&client);
        let sem = Arc::clone(&sem);
        set.spawn(async move {
            let _permit = sem.acquire_owned().await.expect("semaphore is not closed");
            let result = email::lookup(&client, &domain).await;
            (index, domain, result)
        });
    }

    let mut slots: Vec<Option<(String, Result<EmailInfo>)>> =
        (0..domains.len()).map(|_| None).collect();
    while let Some(joined) = set.join_next().await {
        if let Ok((index, domain, result)) = joined {
            slots[index] = Some((domain, result));
        }
    }
    slots
        .into_iter()
        .enumerate()
        .map(|(i, slot)| {
            slot.unwrap_or_else(|| (domains[i].clone(), Err(anyhow!("email task failed"))))
        })
        .collect()
}

async fn run_tls(args: TlsArgs, json: bool) -> Result<ExitCode> {
    let domains = gather_domains(&args.input)?;
    let results = tls_all(&domains, args.port, args.input.concurrency).await;
    let errors = results.iter().filter(|(_, r)| r.is_err()).count();

    if json {
        let arr: Vec<Value> = results
            .iter()
            .map(|(domain, result)| match result {
                Ok(info) => serde_json::to_value(info)
                    .unwrap_or_else(|_| json!({ "domain": domain, "error": "serialize failed" })),
                Err(e) => json!({ "domain": domain, "error": format!("{e:#}") }),
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&arr)?);
    } else {
        for (domain, result) in &results {
            match result {
                Ok(info) => output::print_tls(info),
                Err(e) => output::print_lookup_error(domain, "tls", e),
            }
        }
    }

    Ok(exit_code(errors))
}

/// Inspect every domain's TLS certificate concurrently, in input order.
async fn tls_all(
    domains: &[String],
    port: u16,
    concurrency: usize,
) -> Vec<(String, Result<TlsInfo>)> {
    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut set = tokio::task::JoinSet::new();
    for (index, domain) in domains.iter().cloned().enumerate() {
        let sem = Arc::clone(&sem);
        set.spawn(async move {
            let _permit = sem.acquire_owned().await.expect("semaphore is not closed");
            let result = tls::inspect(&domain, port).await;
            (index, domain, result)
        });
    }

    let mut slots: Vec<Option<(String, Result<TlsInfo>)>> =
        (0..domains.len()).map(|_| None).collect();
    while let Some(joined) = set.join_next().await {
        if let Ok((index, domain, result)) = joined {
            slots[index] = Some((domain, result));
        }
    }
    slots
        .into_iter()
        .enumerate()
        .map(|(i, slot)| {
            slot.unwrap_or_else(|| (domains[i].clone(), Err(anyhow!("tls task failed"))))
        })
        .collect()
}

fn run_tlds(category: Option<String>, json: bool) -> Result<ExitCode> {
    match category.as_deref() {
        // List all categories.
        None => {
            if json {
                println!("{}", serde_json::to_string_pretty(tlds::categories())?);
            } else {
                println!("TLD categories (use with `check --category <name>`):");
                for name in tlds::category_names() {
                    let list = tlds::category(name).unwrap_or(&[]);
                    println!("  {name:<11} ({:>2})  {}", list.len(), list.join(" "));
                }
                println!(
                    "\n`all` selects every known TLD ({}).",
                    tlds::all_tlds().len()
                );
            }
        }
        // Every known TLD.
        Some("all") => {
            let all = tlds::all_tlds();
            if json {
                println!("{}", serde_json::to_string_pretty(all)?);
            } else {
                for t in all {
                    println!("{t}");
                }
            }
        }
        // A specific category.
        Some(name) => {
            let list = tlds::category(name).ok_or_else(|| {
                anyhow!(
                    "unknown category `{name}`; available: {}",
                    tlds::category_names().join(", ")
                )
            })?;
            if json {
                println!("{}", serde_json::to_string_pretty(list)?);
            } else {
                for t in list {
                    println!("{t}");
                }
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// If any TLD-spray option is set, expand each input into `label.tld` for every
/// selected TLD (the input's own TLD is dropped). Otherwise return domains as-is.
fn expand_tlds(domains: Vec<String>, args: &LookupArgs) -> Result<Vec<String>> {
    if args.tlds.is_empty() && args.categories.is_empty() && !args.all_tlds {
        return Ok(domains);
    }

    let mut tld_list: Vec<String> = Vec::new();
    let mut seen = HashSet::new();
    if args.all_tlds {
        for t in tlds::all_tlds() {
            add_unique(&mut tld_list, &mut seen, t);
        }
    }
    for t in &args.tlds {
        add_unique(&mut tld_list, &mut seen, t);
    }
    for cat in &args.categories {
        let list = tlds::category(cat).ok_or_else(|| {
            anyhow!(
                "unknown category `{cat}`; see `domain tlds`. available: {}",
                tlds::category_names().join(", ")
            )
        })?;
        for t in list {
            add_unique(&mut tld_list, &mut seen, t);
        }
    }

    let mut out = Vec::new();
    let mut out_seen = HashSet::new();
    for d in &domains {
        let label = d.split('.').next().unwrap_or(d);
        for tld in &tld_list {
            let fqdn = format!("{label}.{tld}");
            if out_seen.insert(fqdn.clone()) {
                out.push(fqdn);
            }
        }
    }
    Ok(out)
}

fn add_unique(list: &mut Vec<String>, seen: &mut HashSet<String>, value: &str) {
    let value = value.trim().trim_start_matches('.').to_ascii_lowercase();
    if !value.is_empty() && seen.insert(value.clone()) {
        list.push(value);
    }
}

fn exit_code(errors: usize) -> ExitCode {
    if errors > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
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
