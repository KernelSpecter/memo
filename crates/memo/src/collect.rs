//! Aggregates events from all traced processes into a RunState, then finalizes
//! it into a cache Entry (or decides the run is not cacheable).

use memo_core::cas::Store as Cas;
use memo_core::entry::{Entry, Input, Output};
use memo_core::fingerprint::{
    build_input_fp, compute_listing_fp, read_dir_entries, FileState, InputFp, PreState,
};
use memo_core::paths::{case_fold, PathId};
use memo_core::stat::{file_signature, FType};
use memo_core::Hash;
use memo_proto::{AccessKind, MutateKind, TaintReason};
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// BLAKE3 of a file's content, streamed so large outputs aren't loaded whole.
fn hash_file(path: &Path) -> Option<Hash> {
    let mut f = std::fs::File::open(path).ok()?;
    let mut hasher = blake3::Hasher::new();
    hasher.update_reader(&mut f).ok()?;
    Some(*hasher.finalize().as_bytes())
}

#[derive(Default, Clone)]
struct Obs {
    read: bool,
    meta: bool,
    listed: bool,
}

#[derive(Clone)]
enum PreSnap {
    Absent,
    Dir,
    File {
        size: u64,
        mtime: i64,
        hash: Option<Hash>,
    },
}

pub struct RunState {
    obs: HashMap<PathId, Obs>,
    spelling: HashMap<PathId, String>,
    premutated: HashMap<PathId, PreSnap>,
    mutated: HashSet<PathId>,
    hello_pids: HashSet<u32>,
    new_pids: HashSet<u32>,
    taints: Vec<(TaintReason, String)>,
    run_start: i64,
    ignore_prefixes: Vec<String>,
    allow_network: bool,
}

/// Outcome of finalizing a run.
pub enum Finalized {
    /// Cacheable: store this entry.
    Cacheable(Entry),
    /// Not cacheable, with the reasons (for -v output).
    Tainted(Vec<(TaintReason, String)>),
}

impl RunState {
    pub fn new(memo_dir: &Path, run_start: i64, allow_network: bool) -> Self {
        let mut ignore = Vec::new();
        let mut add = |v: Option<String>| {
            if let Some(s) = v {
                let n = memo_core::paths::normalize(&s).to_lowercase();
                if !n.is_empty() {
                    ignore.push(n);
                }
            }
        };
        add(std::env::var("TEMP").ok());
        add(std::env::var("TMP").ok());
        add(std::env::var("SystemRoot").ok());
        add(Some(memo_dir.to_string_lossy().into_owned()));
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            add(Some(format!("{}\\npm-cache\\_logs", local)));
        }
        if let Ok(extra) = std::env::var("MEMO_IGNORE") {
            for p in extra.split(';').filter(|s| !s.is_empty()) {
                add(Some(p.to_string()));
            }
        }
        RunState {
            obs: HashMap::new(),
            spelling: HashMap::new(),
            premutated: HashMap::new(),
            mutated: HashSet::new(),
            hello_pids: HashSet::new(),
            new_pids: HashSet::new(),
            taints: Vec::new(),
            run_start,
            ignore_prefixes: ignore,
            allow_network,
        }
    }

    fn ignored(&self, path: &str) -> bool {
        let n = memo_core::paths::normalize(path).to_lowercase();
        self.ignore_prefixes.iter().any(|pre| {
            n == *pre || n.starts_with(&format!("{}\\", pre))
        })
    }

    fn remember(&mut self, path: &str) -> PathId {
        let id = PathId::new(path);
        self.spelling
            .entry(id.clone())
            .or_insert_with(|| memo_core::paths::normalize(path));
        id
    }

    pub fn on_access(&mut self, kind: AccessKind, path: &str) {
        if self.ignored(path) {
            return;
        }
        let id = self.remember(path);
        let o = self.obs.entry(id).or_default();
        match kind {
            AccessKind::Read => o.read = true,
            AccessKind::Probe | AccessKind::ProbeAbsent => o.meta = true,
            AccessKind::List => o.listed = true,
        }
    }

    /// Snapshot the pre-run state of a path being mutated. Called by the pipe
    /// handler; the ack is sent by the caller after this returns.
    pub fn on_premutate(&mut self, path: &str) {
        if self.ignored(path) {
            return;
        }
        let id = self.remember(path);
        self.mutated.insert(id.clone());
        if self.premutated.contains_key(&id) {
            return;
        }
        // Hash even if nothing has read the path yet: a read may come after
        // this write (cargo reading back the .d file rustc just rewrote), and
        // what it sees can still depend on the pre-run content (an append).
        // finalize() uses the hash only if the path was read.
        let snap = match file_signature(Path::new(path)) {
            None => PreSnap::Absent,
            Some(sig) if sig.ftype == FType::Dir => PreSnap::Dir,
            Some(sig) => PreSnap::File {
                size: sig.size,
                mtime: sig.mtime,
                hash: hash_file(Path::new(path)),
            },
        };
        self.premutated.insert(id, snap);
    }

    pub fn on_mutate(&mut self, _kind: MutateKind, path: &str, target: Option<&str>) {
        if !self.ignored(path) {
            let id = self.remember(path);
            self.mutated.insert(id);
        }
        if let Some(t) = target {
            if !self.ignored(t) {
                let id = self.remember(t);
                self.mutated.insert(id);
            }
        }
    }

    pub fn on_hello(&mut self, pid: u32) {
        self.hello_pids.insert(pid);
    }

    pub fn on_new_pid(&mut self, pid: u32) {
        self.new_pids.insert(pid);
    }

    pub fn on_taint(&mut self, reason: TaintReason, detail: String) {
        if reason == TaintReason::Network && self.allow_network {
            return;
        }
        self.taints.push((reason, detail));
    }

    /// Every process the job saw must have checked in (sent Hello). One that
    /// didn't means we could not trace it.
    pub fn check_hello_accounting(&mut self) {
        let missing: Vec<u32> = self
            .new_pids
            .iter()
            .filter(|p| !self.hello_pids.contains(p))
            .copied()
            .collect();
        for pid in missing {
            self.taints
                .push((TaintReason::NoHello, format!("pid {} never checked in", pid)));
        }
    }

    /// Finalize into an Entry or a taint list.
    pub fn finalize(
        &mut self,
        argv: Vec<String>,
        cwd: String,
        duration_ms: u64,
        exit_code: i32,
        console: Hash,
        cas: &Cas,
        cache_failures: bool,
    ) -> Finalized {
        self.check_hello_accounting();
        if exit_code != 0 && !cache_failures {
            self.taints
                .push((TaintReason::NonZeroExit, format!("exit code {}", exit_code)));
        }

        // Build inputs from observed paths.
        let mut inputs: Vec<Input> = Vec::new();
        for (id, o) in &self.obs {
            let path = self.spelling.get(id).cloned().unwrap_or_default();
            let mutated = self.mutated.contains(id);
            if mutated {
                // Pre-run state from the snapshot.
                let snap = self.premutated.get(id);
                let pre = match snap {
                    Some(PreSnap::Absent) | None => PreState::Absent,
                    Some(PreSnap::Dir) => PreState::Dir { listing: None },
                    Some(PreSnap::File { size, mtime, hash }) => {
                        if o.read && hash.is_none() {
                            // The snapshot couldn't read the pre-run content
                            // (e.g. locked), so we can't prove what was read.
                            self.taints.push((
                                TaintReason::InternalError,
                                format!("could not hash pre-run content of {}", path),
                            ));
                            PreState::File {
                                size: *size,
                                mtime: Some(*mtime),
                                hash: None,
                            }
                        } else {
                            PreState::File {
                                size: *size,
                                mtime: if o.meta { Some(*mtime) } else { None },
                                hash: if o.read { *hash } else { None },
                            }
                        }
                    }
                };
                inputs.push(Input {
                    path,
                    fp: build_input_fp(pre, true),
                });
            } else {
                // Not mutated: current state == pre-run state.
                match file_signature(Path::new(&path)) {
                    None => {
                        inputs.push(Input {
                            path,
                            fp: InputFp::Absent,
                        });
                    }
                    Some(sig) if sig.ftype == FType::Dir => {
                        let listing = if o.listed {
                            read_dir_entries(Path::new(&path))
                                .ok()
                                .map(|entries| compute_listing_fp(&entries, &self.mutated_names_in(&path)))
                        } else {
                            None
                        };
                        inputs.push(Input {
                            path,
                            fp: InputFp::Dir { listing },
                        });
                    }
                    Some(sig) => {
                        // External modification check: content changed during
                        // the run by someone other than the tree.
                        if (o.read || o.meta) && sig.change_time > self.run_start {
                            self.taints.push((
                                TaintReason::ExternalModification,
                                format!("{} changed during the run", path),
                            ));
                        }
                        let hash = if o.read {
                            std::fs::read(&path).ok().map(|b| *blake3::hash(&b).as_bytes())
                        } else {
                            None
                        };
                        inputs.push(Input {
                            path,
                            fp: InputFp::File {
                                size: sig.size,
                                mtime: if o.meta { Some(sig.mtime) } else { None },
                                hash,
                            },
                        });
                    }
                }
            }
        }

        // Build outputs from mutated paths (see needs_output for the skips).
        let mut outputs: Vec<Output> = Vec::new();
        for id in &self.mutated {
            let path = self.spelling.get(id).cloned().unwrap_or_default();
            if path.is_empty() {
                continue;
            }
            let final_state = current_state(Path::new(&path), cas);
            let pre = self.premutated.get(id);
            if !needs_output(pre, self.obs.get(id), &final_state) {
                continue;
            }
            outputs.push(Output {
                path,
                state: final_state,
            });
        }

        if !self.taints.is_empty() {
            return Finalized::Tainted(std::mem::take(&mut self.taints));
        }

        Finalized::Cacheable(Entry {
            format: memo_core::FORMAT_VERSION,
            argv,
            cwd,
            created: unix_now(),
            duration_ms,
            exit_code,
            inputs,
            outputs,
            console,
        })
    }

    /// Case-folded names of mutated entries directly inside `dir`.
    fn mutated_names_in(&self, dir: &str) -> HashSet<String> {
        let dir_id = PathId::new(dir).0;
        let prefix = format!("{}\\", dir_id);
        let mut names = HashSet::new();
        for id in &self.mutated {
            if let Some(rest) = id.0.strip_prefix(&prefix) {
                if !rest.contains('\\') {
                    names.insert(rest.to_string());
                }
            }
        }
        // Also spelled forms.
        for id in &self.mutated {
            if let Some(spelled) = self.spelling.get(id) {
                let sid = PathId::new(spelled).0;
                if let Some(rest) = sid.strip_prefix(&prefix) {
                    if !rest.contains('\\') {
                        names.insert(case_fold(rest));
                    }
                }
            }
        }
        names
    }

    pub fn taints(&self) -> &[(TaintReason, String)] {
        &self.taints
    }
}

fn current_state(path: &Path, cas: &Cas) -> FileState {
    match file_signature(path) {
        None => FileState::Absent,
        Some(sig) if sig.ftype == FType::Dir => FileState::Dir,
        Some(sig) => {
            let readonly = std::fs::metadata(path)
                .map(|m| m.permissions().readonly())
                .unwrap_or(false);
            let content = cas.put_file(path).unwrap_or([0u8; 32]);
            FileState::File {
                size: sig.size,
                mtime: sig.mtime,
                readonly,
                content,
            }
        }
    }
}

/// Whether a mutated path's final state must be recorded as an output. It may
/// be skipped only if it equals the pre-run state *and* an input fingerprint
/// pins that state, so verification guarantees it holds again at replay time.
/// A path that was never observed has no input: its replay-time state is
/// arbitrary, so it is always recorded (e.g. an unread file rewritten with the
/// same bytes, or a temp file created and deleted during the run).
fn needs_output(pre: Option<&PreSnap>, obs: Option<&Obs>, final_state: &FileState) -> bool {
    let Some(o) = obs else { return true };
    match (pre, final_state) {
        // Inputs pin existence and type.
        (Some(PreSnap::Absent) | None, FileState::Absent) => false,
        (Some(PreSnap::Dir), FileState::Dir) => false,
        // Content is pinned only if the path was read (hash iff read).
        (
            Some(PreSnap::File {
                hash: Some(h), ..
            }),
            FileState::File { content, .. },
        ) => !o.read || h != content,
        // Type changed, or pre content unknown: record it (safe).
        _ => true,
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Current time as a Windows FILETIME (100ns since 1601), for the external-mod
/// check.
pub fn now_filetime() -> i64 {
    // 11644473600 seconds between 1601-01-01 and 1970-01-01.
    let unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let ticks = (unix.as_secs() as i64 + 11_644_473_600) * 10_000_000
        + (unix.subsec_nanos() as i64) / 100;
    ticks
}
