mod backend;
mod cli;
mod date;
mod dns;
mod dnssec;
mod email;
mod http;
mod output;
mod pricing;
mod propagation;
mod tlds;
mod tls;

use std::collections::HashSet;
use std::io::{IsTerminal, Read};
use std::net::IpAddr;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use clap::{CommandFactory, Parser};
use serde_json::{Value, json};
use tokio::sync::Semaphore;

use crate::backend::{Availability, Backend, DomainInfo};
use crate::cli::{
    BatchInput, Cli, Command, DnsArgs, LookupArgs, PriceArgs, PropagationArgs, TlsArgs,
};
use crate::dns::{DEFAULT_TYPES, DnsClient, DnsRecord};
use crate::email::EmailInfo;
use crate::pricing::{PROVIDER, PriceClient, TldPrice};
use crate::tls::TlsInfo;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let json = cli.json;
    let result = match cli.command {
        Some(command) => run(command, json).await,
        // No subcommand: `domain <name>` — availability + WHOIS-if-registered.
        None => run_default(cli.default, json).await,
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Check,
    Whois,
    /// Default `domain <name>`: availability, plus WHOIS for registered names.
    Lookup,
}

/// The default action when no subcommand is given.
async fn run_default(args: LookupArgs, json: bool) -> Result<ExitCode> {
    // Bare `domain` on a terminal with no input: show help instead of erroring.
    if !json
        && args.input.domains.is_empty()
        && args.input.file.is_none()
        && std::io::stdin().is_terminal()
    {
        Cli::command().print_help().ok();
        println!();
        return Ok(ExitCode::SUCCESS);
    }
    run_lookups(args, Mode::Lookup, json).await
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
        Command::Ptr(input) => run_ptr(input, json).await,
        Command::Dnssec(input) => run_dnssec(input, json).await,
        Command::Http(input) => run_http(input, json).await,
        Command::Propagation(args) => run_propagation(args, json).await,
        Command::Price(args) => run_price(args, json).await,
        Command::Completions { shell } => {
            let mut cmd = Cli::command();
            let name = cmd.get_name().to_string();
            clap_complete::generate(shell, &mut cmd, name, &mut std::io::stdout());
            Ok(ExitCode::SUCCESS)
        }
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

    // Pricing is opt-in via --pricing (Porkbun's keyless pricing endpoint is
    // slow, ~15s); it's off by default for every mode, including the default
    // `domain <name>` lookup.
    let want_prices = args.pricing;

    // Fetch pricing (the full Porkbun table) concurrently with the availability
    // lookups rather than before them — otherwise the pricing download adds its
    // full latency on top of every run. Pricing is best-effort: a fetch failure
    // shouldn't fail the availability run.
    let prices_fut = async {
        if !want_prices {
            return None;
        }
        match PriceClient::new().fetch_all().await {
            Ok(map) => Some(map),
            Err(e) => {
                eprintln!("warning: could not fetch pricing: {e:#}");
                None
            }
        }
    };
    let lookups_fut = lookup_all(Arc::new(backend), &domains, args.input.concurrency);
    let (prices, mut results) = tokio::join!(prices_fut, lookups_fut);

    let price_of = |domain: &str| -> Option<&TldPrice> {
        let prices = prices.as_ref()?;
        prices.get(tld_label(domain))
    };

    let errors = results.iter().filter(|(_, r)| r.is_err()).count();

    // `whois --expiring-within 30d`: keep only domains whose expiry parses and
    // falls within the window, sorted soonest-first. Errors are dropped from the
    // view but still counted toward the exit code above.
    if let (Mode::Whois, Some(window)) = (mode, args.expiring_within.as_deref()) {
        let max_days = date::parse_duration_days(window)?;
        let days_of = |r: &Result<DomainInfo>| -> Option<i64> {
            r.as_ref()
                .ok()?
                .expires
                .as_deref()
                .and_then(date::days_until)
        };
        results.retain(|(_, r)| days_of(r).map(|d| d <= max_days).unwrap_or(false));
        results.sort_by_key(|(_, r)| days_of(r).unwrap_or(i64::MAX));
    }

    if json {
        let arr: Vec<Value> = results
            .iter()
            .map(|(domain, result)| match result {
                Ok(info) => {
                    let mut v =
                        serde_json::to_value(info).unwrap_or_else(|_| json!({ "domain": domain }));
                    if let Some(p) = price_of(&info.domain) {
                        v["price"] = json!({
                            "registration": p.registration,
                            "renewal": p.renewal,
                            "transfer": p.transfer,
                            "source": PROVIDER,
                        });
                    }
                    v
                }
                Err(e) => json!({ "domain": domain, "error": format!("{e:#}") }),
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&arr)?);
    } else {
        let mut summary = output::Summary::default();
        for (domain, result) in &results {
            match result {
                Ok(info) => {
                    let price = || {
                        price_of(&info.domain)
                            .map(|p| format!("${}/yr ({PROVIDER})", p.registration))
                    };
                    match mode {
                        Mode::Check => output::print_check(info, price().as_deref()),
                        Mode::Whois => output::print_whois(info),
                        Mode::Lookup => {
                            output::print_check(info, price().as_deref());
                            // Not available → also print the full WHOIS record.
                            if info.availability != Availability::Available {
                                output::print_whois(info);
                            }
                        }
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

/// The TLD label (last dotted component) of a domain, lowercased-as-given.
fn tld_label(domain: &str) -> &str {
    domain.rsplit('.').next().unwrap_or(domain)
}

async fn run_price(args: PriceArgs, json: bool) -> Result<ExitCode> {
    let prices = PriceClient::new().fetch_all().await?;

    let mut tld_list = Vec::new();
    let mut seen = HashSet::new();
    if args.all {
        let mut keys: Vec<&String> = prices.keys().collect();
        keys.sort();
        for k in keys {
            add_unique(&mut tld_list, &mut seen, k);
        }
    }
    for item in &args.items {
        add_unique(&mut tld_list, &mut seen, tld_label(item));
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
    if tld_list.is_empty() {
        bail!("give a TLD, a domain, or --category/--all");
    }

    let results: Vec<(String, Option<TldPrice>)> = tld_list
        .into_iter()
        .map(|tld| {
            let price = prices.get(&tld).cloned();
            (tld, price)
        })
        .collect();

    if json {
        let arr: Vec<Value> = results
            .iter()
            .map(|(tld, price)| match price {
                Some(p) => json!({
                    "tld": tld,
                    "registration": p.registration,
                    "renewal": p.renewal,
                    "transfer": p.transfer,
                    "source": PROVIDER,
                }),
                None => json!({ "tld": tld, "offered": false }),
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&arr)?);
    } else {
        output::print_prices(&results);
    }

    Ok(ExitCode::SUCCESS)
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

async fn run_ptr(input: BatchInput, json: bool) -> Result<ExitCode> {
    let concurrency = input.concurrency;
    let ips = gather_domains(&input)?;
    let client = Arc::new(DnsClient::new());
    let results = run_concurrent(&ips, concurrency, move |raw| {
        let client = Arc::clone(&client);
        async move {
            let ip: IpAddr = raw
                .trim()
                .parse()
                .with_context(|| format!("`{raw}` is not a valid IP address"))?;
            let recs = client.lookup(&dns::reverse_name(ip), "PTR").await?;
            Ok::<Vec<String>, anyhow::Error>(recs.into_iter().map(|r| r.value).collect())
        }
    })
    .await;
    let errors = results.iter().filter(|(_, r)| r.is_err()).count();

    if json {
        let arr: Vec<Value> = results
            .iter()
            .map(|(ip, r)| match r {
                Ok(names) => json!({ "ip": ip, "ptr": names }),
                Err(e) => json!({ "ip": ip, "error": format!("{e:#}") }),
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&arr)?);
    } else {
        for (ip, r) in &results {
            match r {
                Ok(names) => output::print_ptr(ip, names),
                Err(e) => output::print_lookup_error(ip, "ptr", e),
            }
        }
    }
    Ok(exit_code(errors))
}

async fn run_dnssec(input: BatchInput, json: bool) -> Result<ExitCode> {
    let concurrency = input.concurrency;
    let domains = gather_domains(&input)?;
    let client = Arc::new(DnsClient::new());
    let results = run_concurrent(&domains, concurrency, move |domain| {
        let client = Arc::clone(&client);
        async move { dnssec::inspect(&client, &domain).await }
    })
    .await;
    let errors = results.iter().filter(|(_, r)| r.is_err()).count();

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&to_json(&results, "domain"))?
        );
    } else {
        for (domain, r) in &results {
            match r {
                Ok(info) => output::print_dnssec(info),
                Err(e) => output::print_lookup_error(domain, "dnssec", e),
            }
        }
    }
    Ok(exit_code(errors))
}

async fn run_http(input: BatchInput, json: bool) -> Result<ExitCode> {
    let concurrency = input.concurrency;
    let targets = gather_domains(&input)?;
    let results = run_concurrent(&targets, concurrency, |target| async move {
        http::inspect(&target).await
    })
    .await;
    let errors = results.iter().filter(|(_, r)| r.is_err()).count();

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&to_json(&results, "url"))?
        );
    } else {
        for (target, r) in &results {
            match r {
                Ok(info) => output::print_http(info),
                Err(e) => output::print_lookup_error(target, "http", e),
            }
        }
    }
    Ok(exit_code(errors))
}

async fn run_propagation(args: PropagationArgs, json: bool) -> Result<ExitCode> {
    let concurrency = args.input.concurrency;
    let domains = gather_domains(&args.input)?;
    let rtype = args.record_type.to_ascii_uppercase();
    let client = Arc::new(DnsClient::new());
    let results = run_concurrent(&domains, concurrency, move |domain| {
        let client = Arc::clone(&client);
        let rtype = rtype.clone();
        async move { propagation::check(&client, &domain, &rtype).await }
    })
    .await;
    let errors = results.iter().filter(|(_, r)| r.is_err()).count();

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&to_json(&results, "domain"))?
        );
    } else {
        for (domain, r) in &results {
            match r {
                Ok(info) => output::print_propagation(info),
                Err(e) => output::print_lookup_error(domain, "propagation", e),
            }
        }
    }
    Ok(exit_code(errors))
}

/// Serialize a batch of `(key, Result<T>)` into a JSON array, using `key_field`
/// (e.g. `"domain"`) as the identifying field on error entries.
fn to_json<T: serde::Serialize>(results: &[(String, Result<T>)], key_field: &str) -> Vec<Value> {
    results
        .iter()
        .map(|(key, r)| match r {
            Ok(info) => serde_json::to_value(info)
                .unwrap_or_else(|_| json!({ key_field: key, "error": "serialize failed" })),
            Err(e) => json!({ key_field: key, "error": format!("{e:#}") }),
        })
        .collect()
}

/// Run `f` over every item concurrently (bounded by `concurrency`), returning
/// `(item, result)` pairs in the original input order.
async fn run_concurrent<T, F, Fut>(
    items: &[String],
    concurrency: usize,
    f: F,
) -> Vec<(String, Result<T>)>
where
    F: Fn(String) -> Fut + Clone + Send + 'static,
    Fut: std::future::Future<Output = Result<T>> + Send,
    T: Send + 'static,
{
    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut set = tokio::task::JoinSet::new();
    for (index, item) in items.iter().cloned().enumerate() {
        let sem = Arc::clone(&sem);
        let f = f.clone();
        set.spawn(async move {
            let _permit = sem.acquire_owned().await.expect("semaphore is not closed");
            let result = f(item.clone()).await;
            (index, item, result)
        });
    }

    let mut slots: Vec<Option<(String, Result<T>)>> = (0..items.len()).map(|_| None).collect();
    while let Some(joined) = set.join_next().await {
        if let Ok((index, item, result)) = joined {
            slots[index] = Some((item, result));
        }
    }
    slots
        .into_iter()
        .enumerate()
        .map(|(i, slot)| slot.unwrap_or_else(|| (items[i].clone(), Err(anyhow!("task failed")))))
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
