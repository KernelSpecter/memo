//! Orchestration: compute the key, try to replay from cache, otherwise launch
//! the command traced, finalize, and store.

use crate::cli::Flags;
use crate::collect::{now_filetime, Finalized, RunState};
use crate::launch::{launch, replay_console, ConsoleLog};
use crate::resolve::{resolve, ResolvedCommand};
use crate::server::PipeServer;
use crate::{current_env, memo_dir};
use anyhow::{anyhow, Result};
use memo_core::entry::Entry;
use memo_core::fingerprint::FileState;
use memo_core::statcache::{hash_of_shared, StatCache};
use memo_core::store::{LastRun, Store};
use memo_core::verify::{first_mismatch, verify_entry};
use memo_proto::RunPayload;
use std::io::IsTerminal;
use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

static PIPE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn dll_path() -> Result<std::path::PathBuf> {
    let exe = std::env::current_exe()?;
    let dir = exe
        .parent()
        .ok_or_else(|| anyhow!("cannot locate memo.exe directory"))?;
    let dll = dir.join("memo_hook.dll");
    if !dll.exists() {
        return Err(anyhow!(
            "memo_hook.dll not found next to memo.exe at {}",
            dll.display()
        ));
    }
    Ok(dll)
}

struct Prepared {
    resolved: ResolvedCommand,
    key: String,
    cwd: String,
    argv: Vec<String>,
    env: std::collections::BTreeMap<String, String>,
}

/// Build the environment the child will run with. When memo's own stdout is a
/// terminal (and the user didn't opt out), force color output so captured — and
/// later replayed — output is colored, matching an un-memoized interactive run.
/// These vars are part of the key, so terminal and redirected runs cache
/// separately (see design §7.4).
fn effective_env(flags: &Flags) -> std::collections::BTreeMap<String, String> {
    let mut env = current_env();
    if !flags.no_color_env && std::io::stdout().is_terminal() {
        for (k, v) in [
            ("FORCE_COLOR", "1"),
            ("CLICOLOR_FORCE", "1"),
            ("CARGO_TERM_COLOR", "always"),
            ("PY_COLORS", "1"),
        ] {
            env.entry(k.to_string()).or_insert_with(|| v.to_string());
        }
    }
    env
}

fn prepare(argv: &[String], flags: &Flags, statcache: &Mutex<StatCache>) -> Result<Prepared> {
    let resolved = resolve(argv)?;
    let cwd = std::env::current_dir()?.to_string_lossy().into_owned();
    let env = effective_env(flags);
    let app_hash = hash_of_shared(statcache, &resolved.target).unwrap_or([0u8; 32]);
    let key = memo_core::key::compute_key(&cwd, argv, &env, &app_hash);
    Ok(Prepared {
        resolved,
        key,
        cwd,
        argv: argv.to_vec(),
        env,
    })
}

pub fn execute(argv: &[String], flags: &Flags) -> Result<ExitCode> {
    if argv.is_empty() {
        return Err(anyhow!("no command given"));
    }
    let store = Store::open(memo_dir());
    let statcache = Mutex::new(StatCache::load(store.statcache_path()));

    let prep = prepare(argv, flags, &statcache)?;

    // Record last run context for `explain`.
    let _ = store.record_last(&LastRun {
        key: prep.key.clone(),
        cwd: prep.cwd.clone(),
        argv: prep.argv.clone(),
        env: prep.env.clone(),
    });

    // Try replay.
    if !flags.no_read {
        for (id, entry) in store.load_entries(&prep.key) {
            if verify_entry(&entry, &statcache) {
                match replay(&store, &entry, flags) {
                    Ok(code) => {
                        store.touch(&prep.key, &id);
                        store.record_hit(entry.duration_ms);
                        save_statcache(&statcache);
                        return Ok(code);
                    }
                    Err(e) => {
                        // The inputs matched but restoring the recorded result
                        // failed — a locked output, or a corrupt/missing blob.
                        // Don't fail the command and don't leave a half-restored
                        // tree: fall back to running it for real (spec §10). The
                        // real run re-stores a fresh, valid entry.
                        if flags.verbose {
                            eprintln!("memo: replay failed ({}); running the command", e);
                        }
                        break;
                    }
                }
            }
        }
    }

    // Miss (or replay fell back): launch traced.
    let code = launch_and_store(&store, &prep, flags)?;
    save_statcache(&statcache);
    Ok(code)
}

fn replay(store: &Store, entry: &Entry, flags: &Flags) -> Result<ExitCode> {
    restore_outputs(store, entry)?;
    replay_console(&decode_console(store, entry)?);
    status_line(
        flags,
        &format!(
            "memo \u{26a1} replayed (saved {:.1}s)",
            entry.duration_ms as f64 / 1000.0
        ),
    );
    Ok(ExitCode::from(clamp_code(entry.exit_code)))
}

fn launch_and_store(store: &Store, prep: &Prepared, flags: &Flags) -> Result<ExitCode> {
    let dll = dll_path()?;
    let dll_ansi: Vec<u8> = dll
        .to_string_lossy()
        .bytes()
        .chain(std::iter::once(0))
        .collect();

    let pipe_name = format!(
        "\\\\.\\pipe\\memo-{}-{}",
        std::process::id(),
        PIPE_COUNTER.fetch_add(1, Ordering::SeqCst)
    );
    let run_id = now_filetime() as u64;
    let payload = RunPayload::new(&pipe_name, run_id);

    let state = std::sync::Arc::new(Mutex::new(RunState::new(
        &memo_dir(),
        now_filetime(),
        flags.allow_network,
    )));

    let server = PipeServer::start(pipe_name.clone(), state.clone())?;

    let ctrl = crate::interrupt::Guard::install();
    let t0 = std::time::Instant::now();
    let result = launch(
        &prep.resolved.app,
        &prep.resolved.cmdline,
        &prep.cwd,
        &dll_ansi,
        &payload,
        &prep.env,
    );
    let duration_ms = t0.elapsed().as_millis() as u64;

    // Ensure all messages are folded in before finalizing.
    server.shutdown();
    let interrupted = ctrl.interrupted();
    drop(ctrl);

    let result = result?;

    {
        let mut s = state.lock().unwrap();
        for pid in &result.new_pids {
            s.on_new_pid(*pid);
        }
        if interrupted {
            s.on_taint(
                memo_proto::TaintReason::Interrupted,
                "Ctrl+C/Ctrl+Break reached memo".into(),
            );
        }
        if result.outlived {
            s.on_taint(
                memo_proto::TaintReason::Outlived,
                "a process outlived the command".into(),
            );
        }
    }

    // Store the console log as a blob.
    let cas = store.cas();
    let console_bytes = postcard::to_stdvec(&result.console).unwrap_or_default();
    let console_hash = cas.put_bytes(&console_bytes).unwrap_or([0u8; 32]);

    let finalized = {
        let mut s = state.lock().unwrap();
        s.finalize(
            prep.argv.clone(),
            prep.cwd.clone(),
            duration_ms,
            result.exit_code,
            console_hash,
            &cas,
            flags.cache_failures,
        )
    };

    match finalized {
        Finalized::Cacheable(entry) => {
            let n_in = entry.inputs.len();
            let n_out = entry.outputs.len();
            if store.put_entry(&prep.key, &entry).is_ok() {
                store.record_store();
                status_line(
                    flags,
                    &format!(
                        "memo \u{25cf} cached ({:.1}s \u{b7} {} inputs \u{b7} {} outputs)",
                        duration_ms as f64 / 1000.0,
                        n_in,
                        n_out
                    ),
                );
            }
        }
        Finalized::Tainted(reasons) => {
            let reason = reasons
                .first()
                .map(|(r, d)| format!("{} ({})", r.human(), d))
                .unwrap_or_else(|| "unknown".into());
            status_line(flags, &format!("memo \u{25cb} not cached: {}", reason));
            if flags.verbose {
                for (r, d) in &reasons {
                    eprintln!("  - {}: {}", r.human(), d);
                }
            }
        }
    }

    Ok(ExitCode::from(clamp_code(result.exit_code)))
}

fn restore_outputs(store: &Store, entry: &Entry) -> Result<()> {
    let cas = store.cas();

    // 1. Deletions, deepest path first.
    let mut deletions: Vec<&str> = entry
        .outputs
        .iter()
        .filter(|o| matches!(o.state, FileState::Absent))
        .map(|o| o.path.as_str())
        .collect();
    deletions.sort_by_key(|p| std::cmp::Reverse(p.len()));
    for p in deletions {
        let path = Path::new(p);
        if path.is_dir() {
            let _ = std::fs::remove_dir_all(path);
        } else if path.exists() {
            let _ = std::fs::remove_file(path);
        }
    }

    // 2. Directory creations, shallowest first.
    let mut dirs: Vec<&str> = entry
        .outputs
        .iter()
        .filter(|o| matches!(o.state, FileState::Dir))
        .map(|o| o.path.as_str())
        .collect();
    dirs.sort_by_key(|p| p.len());
    for p in dirs {
        std::fs::create_dir_all(p)?;
    }

    // 3. Files.
    for o in &entry.outputs {
        if let FileState::File {
            content,
            mtime,
            readonly,
            ..
        } = &o.state
        {
            let dest = Path::new(&o.path);
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let bytes = cas
                .read_verified(content)
                .map_err(|e| anyhow!("cached output blob for {} unusable: {}", o.path, e))?;
            let tmp = dest.with_extension(format!("memo-tmp-{}", std::process::id()));
            std::fs::write(&tmp, &bytes)?;
            // Propagate a failed restore (e.g. the destination is locked) rather
            // than swallowing it and leaving stale content; clean up the temp.
            std::fs::rename(&tmp, dest)
                .or_else(|_| {
                    let _ = std::fs::remove_file(dest);
                    std::fs::rename(&tmp, dest)
                })
                .map_err(|e| {
                    let _ = std::fs::remove_file(&tmp);
                    anyhow!("could not restore output {}: {}", o.path, e)
                })?;
            set_file_mtime(dest, *mtime);
            if *readonly {
                if let Ok(md) = std::fs::metadata(dest) {
                    let mut perms = md.permissions();
                    perms.set_readonly(true);
                    let _ = std::fs::set_permissions(dest, perms);
                }
            }
        }
    }
    Ok(())
}

fn set_file_mtime(path: &Path, filetime: i64) {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::Storage::FileSystem::{SetFileTime, FILE_FLAG_BACKUP_SEMANTICS};

    let file = match std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
    {
        Ok(f) => f,
        Err(_) => return,
    };
    let ft = FILETIME {
        dwLowDateTime: (filetime as u64 & 0xFFFF_FFFF) as u32,
        dwHighDateTime: ((filetime as u64 >> 32) & 0xFFFF_FFFF) as u32,
    };
    let handle = file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
    unsafe {
        SetFileTime(handle, std::ptr::null(), std::ptr::null(), &ft);
    }
}

fn decode_console(store: &Store, entry: &Entry) -> Result<ConsoleLog> {
    let bytes = store
        .cas()
        .read_verified(&entry.console)
        .map_err(|e| anyhow!("cached console blob unusable: {}", e))?;
    postcard::from_bytes(&bytes).map_err(|e| anyhow!("could not decode cached console: {}", e))
}

fn save_statcache(statcache: &Mutex<StatCache>) {
    let _ = statcache.lock().unwrap().save();
}

fn status_line(flags: &Flags, msg: &str) {
    if flags.quiet {
        return;
    }
    // Normally only shown on an interactive terminal; MEMO_FORCE_STATUS makes it
    // unconditional (used by tests and scripts that capture stderr).
    if std::io::stderr().is_terminal() || std::env::var_os("MEMO_FORCE_STATUS").is_some() {
        eprintln!("{}", msg);
    }
}

/// Exit codes above 255 don't fit in ExitCode; clamp while preserving zero/nonzero.
fn clamp_code(code: i32) -> u8 {
    if code == 0 {
        0
    } else {
        (code & 0xff) as u8 | if code & 0xff == 0 { 1 } else { 0 }
    }
}

pub fn explain(argv: &[String]) -> Result<ExitCode> {
    if argv.is_empty() {
        return Err(anyhow!("usage: memo explain <command> ..."));
    }
    let store = Store::open(memo_dir());
    let statcache = Mutex::new(StatCache::load(store.statcache_path()));
    let prep = prepare(argv, &Flags::default(), &statcache)?;

    let entries = store.load_entries(&prep.key);
    if entries.is_empty() {
        println!("memo: no cached run for this command in this directory");
        return Ok(ExitCode::SUCCESS);
    }
    let (_, entry) = &entries[0];
    match first_mismatch(entry, &statcache) {
        None => println!(
            "memo: would replay — all {} inputs match",
            entry.inputs.len()
        ),
        Some(inp) => {
            println!("memo: would miss — first changed input:");
            println!("  {}", inp.path);
            println!("  (recorded fingerprint no longer matches the file on disk)");
        }
    }
    Ok(ExitCode::SUCCESS)
}
