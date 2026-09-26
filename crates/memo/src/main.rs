//! memo — zero-config command result caching for Windows.

mod cli;
mod collect;
mod launch;
mod resolve;
mod run;
mod server;

use anyhow::Result;
use memo_core::store::Store;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;

/// Root directory of the cache (%LOCALAPPDATA%\memo, override MEMO_DIR).
pub fn memo_dir() -> PathBuf {
    if let Ok(d) = std::env::var("MEMO_DIR") {
        return PathBuf::from(d);
    }
    let base = std::env::var("LOCALAPPDATA")
        .unwrap_or_else(|_| std::env::var("TEMP").unwrap_or_else(|_| ".".to_string()));
    PathBuf::from(base).join("memo")
}

/// Collect the current process environment into a sorted map.
pub fn current_env() -> BTreeMap<String, String> {
    std::env::vars().collect()
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match cli::parse(&args) {
        cli::Command::Help => {
            print_help();
            ExitCode::SUCCESS
        }
        cli::Command::Stats => match do_stats() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(e),
        },
        cli::Command::Gc { max_bytes } => match do_gc(max_bytes) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(e),
        },
        cli::Command::Clear => match Store::open(memo_dir()).clear() {
            Ok(()) => {
                eprintln!("memo: cache cleared");
                ExitCode::SUCCESS
            }
            Err(e) => fail(e.into()),
        },
        cli::Command::Explain { argv } => match run::explain(&argv) {
            Ok(code) => code,
            Err(e) => fail(e),
        },
        cli::Command::Run { argv, flags } => match run::execute(&argv, &flags) {
            Ok(code) => code,
            Err(e) => fail(e),
        },
    }
}

fn fail(e: anyhow::Error) -> ExitCode {
    eprintln!("memo: {:#}", e);
    ExitCode::from(125)
}

fn do_stats() -> Result<()> {
    let s = Store::open(memo_dir()).stats();
    let mb = s.total_bytes as f64 / (1024.0 * 1024.0);
    println!("cache dir:   {}", memo_dir().display());
    println!("entries:     {}", s.entries);
    println!("blobs:       {}", s.blobs);
    println!("size:        {:.1} MiB", mb);
    println!("hits:        {}", s.counters.hits);
    println!("stores:      {}", s.counters.stores);
    println!("time saved:  {:.1} s", s.counters.saved_ms as f64 / 1000.0);
    Ok(())
}

fn do_gc(max_bytes: Option<u64>) -> Result<()> {
    let max = max_bytes.unwrap_or(5 * 1024 * 1024 * 1024);
    let r = Store::open(memo_dir()).gc(max)?;
    eprintln!(
        "memo: gc removed {} entries, {} blobs, freed {:.1} MiB",
        r.removed_entries,
        r.removed_blobs,
        r.freed_bytes as f64 / (1024.0 * 1024.0)
    );
    Ok(())
}

fn print_help() {
    println!(
        "memo — zero-config command result caching\n\n\
USAGE:\n  memo [flags] <command> [args...]\n  memo -- <command> ...\n  memo explain <command> ...\n  memo stats | gc [--max-size SIZE] | clear\n\n\
FLAGS:\n  --cache-failures   cache commands that exit non-zero\n  --allow-network    cache even if the command used the network\n  --no-color-env     do not force color output env vars\n  --no-read          always run; still record a fresh entry\n  -q, --quiet        suppress the status line\n  -v, --verbose      print why a run was not cached"
    );
}
