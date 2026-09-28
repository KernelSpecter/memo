//! Aggregates events from all traced processes into a RunState, then finalizes
//! it into a cache Entry (or decides the run is not cacheable).

use memo_core::cas::Store as Cas;
use memo_core::entry::{Entry, Input, Output};
use memo_core::fingerprint::{
    build_input_fp, compute_listing_fp, read_dir_entries, DirEntry, FileState, InputFp, ListingFp,
    PreState,
};
use memo_core::paths::{case_fold, PathId};
use memo_core::stat::{file_signature, FType};
use memo_core::Hash;
use memo_proto::{AccessKind, MutateKind, TaintReason};
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Whether normalized, lowercased `path` is `prefix` or inside it.
fn under(prefix: &str, path: &str) -> bool {
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('\\'))
}

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
    /// Mutated paths whose pre-run state must be pinned as an input (every
    /// mutation except a pure truncating create-or-replace). A subset of
    /// `mutated`: a Truncate-only path is an output but not an input.
    pin_pre: HashSet<PathId>,
    /// Raw directory entries captured synchronously at the tree's first
    /// enumeration of each directory (PreList), keyed by directory PathId — what
    /// the command was about to see, before it wrote into the directory itself.
    /// The listing fingerprint is computed from these at finalize, once the set
    /// of the tree's own mutated names in each directory is known.
    listings: HashMap<PathId, Vec<DirEntry>>,
    hello_pids: HashSet<u32>,
    new_pids: HashSet<u32>,
    taints: Vec<(TaintReason, String)>,
    run_start: i64,
    ignore_prefixes: Vec<String>,
    /// %SystemRoot%: reads there are ignored, writes taint.
    system_root: Option<String>,
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
        let prefix = |s: &str| {
            let n = memo_core::paths::normalize(s).to_lowercase();
            (!n.is_empty()).then_some(n)
        };
        let mut ignore = Vec::new();
        let mut add = |v: Option<String>| ignore.extend(v.as_deref().and_then(prefix));
        add(std::env::var("TEMP").ok());
        add(std::env::var("TMP").ok());
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
            pin_pre: HashSet::new(),
            listings: HashMap::new(),
            hello_pids: HashSet::new(),
            new_pids: HashSet::new(),
            taints: Vec::new(),
            run_start,
            ignore_prefixes: ignore,
            system_root: std::env::var("SystemRoot").ok().as_deref().and_then(prefix),
            allow_network,
        }
    }

    /// Neither an input nor an output: under an ignored prefix or %SystemRoot%.
    fn ignored(&self, path: &str) -> bool {
        let n = memo_core::paths::normalize(path).to_lowercase();
        self.ignore_prefixes.iter().any(|pre| under(pre, &n))
            || self.system_root.as_deref().is_some_and(|sr| under(sr, &n))
    }

    /// A mutation under %SystemRoot% (and not under another ignored prefix,
    /// e.g. a %TEMP% inside it) changes machine state replay can't restore.
    fn system_write(&self, path: &str) -> bool {
        let n = memo_core::paths::normalize(path).to_lowercase();
        self.system_root.as_deref().is_some_and(|sr| under(sr, &n))
            && !self.ignore_prefixes.iter().any(|pre| under(pre, &n))
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
        // Do NOT mark the path mutated here: a PreMutate only means a mutation
        // was *attempted*. The path is marked mutated by on_mutate, which the
        // hook sends only after the operation succeeds — so an open that fails
        // (e.g. CreateDirectory on an existing dir, a denied write) leaves a
        // snapshot but is never treated as an output or input.
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

    /// Snapshot a directory's contents at the moment the tree first enumerates it
    /// (PreList). Called by the pipe handler; the ack is sent after this returns,
    /// so the snapshot is exactly what the command is about to see — before the
    /// tree writes into the directory itself.
    pub fn on_prelist(&mut self, path: &str) {
        if self.ignored(path) {
            return;
        }
        let id = self.remember(path);
        // Mark it listed so finalize treats the directory as an input.
        self.obs.entry(id.clone()).or_default().listed = true;
        if self.listings.contains_key(&id) {
            return;
        }
        match read_dir_entries(Path::new(path)) {
            Ok(entries) => {
                self.listings.insert(id, entries);
            }
            Err(_) => {
                // Couldn't enumerate what the command is about to read: we can't
                // prove the listing, so the run must not be cached.
                self.taints.push((
                    TaintReason::InternalError,
                    format!("could not snapshot listing of {}", path),
                ));
            }
        }
    }

    pub fn on_mutate(&mut self, kind: MutateKind, path: &str, target: Option<&str>) {
        for p in std::iter::once(path).chain(target) {
            if self.system_write(p) {
                self.taints.push((TaintReason::SystemWrite, p.to_string()));
            }
        }
        let pins = kind.pins_pre_state();
        if !self.ignored(path) {
            let id = self.remember(path);
            self.mutated.insert(id.clone());
            if pins {
                self.pin_pre.insert(id);
            }
        }
        if let Some(t) = target {
            if !self.ignored(t) {
                let id = self.remember(t);
                self.mutated.insert(id.clone());
                if pins {
                    self.pin_pre.insert(id);
                }
            }
        }
    }

    /// The listing fingerprint for a directory that was enumerated: the raw
    /// pre-run entries hashed with the tree's own mutated names in that directory
    /// treated name-only. None if the directory was never enumerated.
    fn listing_fp_for(&self, dir_id: &PathId) -> Option<ListingFp> {
        let entries = self.listings.get(dir_id)?;
        let dir = self.spelling.get(dir_id).cloned().unwrap_or_default();
        Some(compute_listing_fp(entries, &self.mutated_names_in(&dir)))
    }

    /// Case-folded names of mutated entries directly inside `dir` (its own
    /// outputs), for name-only treatment in the listing fingerprint.
    fn mutated_names_in(&self, dir: &str) -> HashSet<String> {
        let prefix = format!("{}\\", PathId::new(dir).0);
        let mut names = HashSet::new();
        for id in &self.mutated {
            if let Some(rest) = id.0.strip_prefix(&prefix) {
                if !rest.contains('\\') {
                    names.insert(rest.to_string());
                }
            }
            if let Some(spelled) = self.spelling.get(id) {
                if let Some(rest) = PathId::new(spelled).0.strip_prefix(&prefix) {
                    if !rest.contains('\\') {
                        names.insert(case_fold(rest));
                    }
                }
            }
        }
        names
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
            self.taints.push((
                TaintReason::NoHello,
                format!("pid {} never checked in", pid),
            ));
        }
    }

    /// Finalize into an Entry or a taint list.
    #[allow(clippy::too_many_arguments)]
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

        // Build inputs from every observed OR mutated path. A path the tree only
        // mutated (never read/probed/listed) must still pin its pre-run state, or
        // the next run would replay regardless of whether that path now exists or
        // differs — e.g. a pure create, an append, a rename source, a delete.
        let mut inputs: Vec<Input> = Vec::new();
        let empty = Obs::default();
        let ids: Vec<PathId> = {
            let mut set: HashSet<PathId> = HashSet::new();
            for id in self
                .obs
                .keys()
                .chain(self.pin_pre.iter())
                .chain(self.listings.keys())
            {
                set.insert(id.clone());
            }
            set.into_iter().collect()
        };
        for id in &ids {
            let path = self.spelling.get(id).cloned().unwrap_or_default();
            if path.is_empty() {
                continue;
            }
            let o = self.obs.get(id).unwrap_or(&empty);
            let mutated = self.mutated.contains(id);
            if mutated {
                // Pre-run state from the snapshot.
                let snap = self.premutated.get(id);
                let pre = match snap {
                    Some(PreSnap::Absent) => PreState::Absent,
                    None => {
                        // A path is marked mutated but has no pre-run snapshot.
                        // In normal operation every mutate is preceded by a
                        // PreMutate that records a snapshot; a missing snapshot
                        // means the PreMutate was skipped (premutate_wait
                        // short-circuits during process teardown) or the client
                        // was unavailable. We cannot prove the pre-run state, so
                        // recording it as Absent could later match a genuinely
                        // absent path and replay a result computed from real
                        // prior content. Taint instead — never cache a run whose
                        // input we could not observe.
                        self.taints.push((
                            TaintReason::InternalError,
                            format!("no pre-run snapshot for mutated path {}", path),
                        ));
                        PreState::Absent
                    }
                    Some(PreSnap::Dir) => PreState::Dir {
                        listing: self.listing_fp_for(id),
                    },
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
                        // Use the pre-run snapshot taken at first enumeration, not
                        // a re-read at finalize (which would include the tree's own
                        // writes into the dir). None if it was never enumerated.
                        let listing = self.listing_fp_for(id);
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
                            std::fs::read(&path)
                                .ok()
                                .map(|b| *blake3::hash(&b).as_bytes())
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
        (Some(PreSnap::File { hash: Some(h), .. }), FileState::File { content, .. }) => {
            !o.read || h != content
        }
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
    (unix.as_secs() as i64 + 11_644_473_600) * 10_000_000 + (unix.subsec_nanos() as i64) / 100
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A dir outside every ignored prefix (%TEMP% etc.), under the build target.
    fn ut_dir(name: &str) -> std::path::PathBuf {
        let base = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("memo-ut")
            .join(format!("{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        base
    }

    /// A path marked mutated with no pre-run snapshot (the PreMutate was skipped,
    /// as premutate_wait does during process teardown) must taint the run, not be
    /// silently recorded as pre-run Absent — else a real prior file would later
    /// match that Absent fingerprint and replay stale.
    #[test]
    fn mutated_path_without_snapshot_taints() {
        let dir = ut_dir("mut_no_snap");
        let file = dir.join("real.txt");
        std::fs::write(&file, b"prior content").unwrap();
        let fs_path = file.to_string_lossy().into_owned();

        let mut rs = RunState::new(&dir.join("cache"), now_filetime(), false);
        // Observed (read) and mutated, but on_premutate was never called: exactly
        // the state the teardown short-circuit leaves behind.
        rs.on_access(AccessKind::Read, &fs_path);
        rs.on_mutate(MutateKind::Write, &fs_path, None);
        assert!(
            !rs.ignored(&fs_path),
            "test path must not be under an ignored prefix"
        );

        let cas = Cas::new(dir.join("cas"));
        match rs.finalize(
            vec!["cmd".into()],
            "cwd".into(),
            0,
            0,
            [0u8; 32],
            &cas,
            false,
        ) {
            Finalized::Tainted(reasons) => assert!(
                reasons
                    .iter()
                    .any(|(r, _)| *r == TaintReason::InternalError),
                "expected an InternalError taint, got {:?}",
                reasons
            ),
            Finalized::Cacheable(_) => {
                panic!("a mutated path with no pre-run snapshot must taint, not cache");
            }
        }
    }
}
