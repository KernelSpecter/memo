//! On-disk cache store: entries keyed by command, a content-addressed blob
//! store, cumulative counters, and garbage collection.

use crate::cas::Store as Cas;
use crate::entry::Entry;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub struct Store {
    root: PathBuf,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Counters {
    pub hits: u64,
    pub stores: u64,
    pub saved_ms: u64,
}

#[derive(Debug, Clone)]
pub struct Stats {
    pub entries: u64,
    pub blobs: u64,
    pub total_bytes: u64,
    pub counters: Counters,
}

#[derive(Debug, Clone)]
pub struct GcReport {
    pub removed_entries: u64,
    pub removed_blobs: u64,
    pub freed_bytes: u64,
}

#[derive(Serialize, Deserialize)]
pub struct LastRun {
    pub key: String,
    pub cwd: String,
    pub argv: Vec<String>,
    pub env: BTreeMap<String, String>,
}

impl Store {
    pub fn open(root: impl AsRef<Path>) -> Self {
        Store {
            root: root.as_ref().to_path_buf(),
        }
    }

    pub fn cas(&self) -> Cas {
        Cas::new(self.root.join("cas"))
    }

    pub fn statcache_path(&self) -> PathBuf {
        self.root.join("statcache.bin")
    }

    fn entries_dir(&self) -> PathBuf {
        self.root.join("entries")
    }

    fn key_dir(&self, key: &str) -> PathBuf {
        self.entries_dir().join(key)
    }

    /// Load all entries for a key, newest first (by file modification time).
    pub fn load_entries(&self, key: &str) -> Vec<(String, Entry)> {
        let dir = self.key_dir(key);
        let mut rows: Vec<(String, std::time::SystemTime, Entry)> = Vec::new();
        let read = match fs::read_dir(&dir) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        for ent in read.flatten() {
            let path = ent.path();
            if path.extension().and_then(|s| s.to_str()) != Some("entry") {
                continue;
            }
            let bytes = match fs::read(&path) {
                Ok(b) => b,
                Err(_) => continue,
            };
            match Entry::decode(&bytes) {
                Some(e) => {
                    let mtime = ent
                        .metadata()
                        .and_then(|m| m.modified())
                        .unwrap_or(std::time::UNIX_EPOCH);
                    let id = path.file_stem().unwrap().to_string_lossy().into_owned();
                    rows.push((id, mtime, e));
                }
                None => {
                    // Corrupt entry: remove it.
                    let _ = fs::remove_file(&path);
                }
            }
        }
        rows.sort_by_key(|r| std::cmp::Reverse(r.1));
        rows.into_iter().map(|(id, _, e)| (id, e)).collect()
    }

    /// Store an entry under a key; returns its id.
    pub fn put_entry(&self, key: &str, entry: &Entry) -> io::Result<String> {
        let dir = self.key_dir(key);
        fs::create_dir_all(&dir)?;
        let id = format!("{}-{}", now_nanos(), std::process::id());
        let dest = dir.join(format!("{}.entry", id));
        let tmp = dir.join(format!("{}.tmp", id));
        fs::write(&tmp, entry.encode())?;
        fs::rename(&tmp, &dest)?;
        Ok(id)
    }

    /// Mark an entry as recently used (touch its modified time) so LRU gc keeps
    /// hot entries.
    pub fn touch(&self, key: &str, id: &str) {
        let path = self.key_dir(key).join(format!("{}.entry", id));
        // Rewriting mtime via opening for append with no bytes is portable
        // enough; use filetime-free approach: set to now by re-opening.
        if let Ok(f) = fs::OpenOptions::new().write(true).open(&path) {
            let _ = f.set_modified(std::time::SystemTime::now());
        }
    }

    pub fn record_last(&self, last: &LastRun) -> io::Result<()> {
        let dir = self.root.join("runs");
        fs::create_dir_all(&dir)?;
        let slot = crate::key::run_slot(&last.cwd, &last.argv);
        let bytes = postcard::to_stdvec(last)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        fs::write(dir.join(format!("{}.last", slot)), bytes)
    }

    pub fn load_last(&self, cwd: &str, argv: &[String]) -> Option<LastRun> {
        let slot = crate::key::run_slot(cwd, argv);
        let bytes = fs::read(self.root.join("runs").join(format!("{}.last", slot))).ok()?;
        postcard::from_bytes(&bytes).ok()
    }

    // --- counters ---

    fn counters_path(&self) -> PathBuf {
        self.root.join("counters.bin")
    }

    pub fn load_counters(&self) -> Counters {
        fs::read(self.counters_path())
            .ok()
            .and_then(|b| postcard::from_bytes(&b).ok())
            .unwrap_or_default()
    }

    fn save_counters(&self, c: &Counters) {
        if let Ok(bytes) = postcard::to_stdvec(c) {
            let _ = fs::create_dir_all(&self.root);
            let _ = fs::write(self.counters_path(), bytes);
        }
    }

    pub fn record_hit(&self, saved_ms: u64) {
        let mut c = self.load_counters();
        c.hits += 1;
        c.saved_ms += saved_ms;
        self.save_counters(&c);
    }

    pub fn record_store(&self) {
        let mut c = self.load_counters();
        c.stores += 1;
        self.save_counters(&c);
    }

    // --- stats & gc ---

    pub fn stats(&self) -> Stats {
        let (entries, _) = count_dir(&self.entries_dir(), "entry");
        let (blobs, blob_bytes) = count_all_files(&self.root.join("cas"));
        let (_, entry_bytes) = count_all_files(&self.entries_dir());
        Stats {
            entries,
            blobs,
            total_bytes: blob_bytes + entry_bytes,
            counters: self.load_counters(),
        }
    }

    pub fn clear(&self) -> io::Result<()> {
        for sub in ["cas", "entries", "runs"] {
            let p = self.root.join(sub);
            if p.exists() {
                fs::remove_dir_all(&p)?;
            }
        }
        let _ = fs::remove_file(self.counters_path());
        let _ = fs::remove_file(self.statcache_path());
        Ok(())
    }

    /// Evict least-recently-used entries until under `max_bytes`, then sweep
    /// blobs no surviving entry references.
    pub fn gc(&self, max_bytes: u64) -> io::Result<GcReport> {
        let before = self.stats().total_bytes;

        // Gather all entries with their mtime and referenced blob hashes.
        let mut all: Vec<(PathBuf, std::time::SystemTime, Entry)> = Vec::new();
        if let Ok(keys) = fs::read_dir(self.entries_dir()) {
            for key in keys.flatten() {
                if !key.path().is_dir() {
                    continue;
                }
                if let Ok(files) = fs::read_dir(key.path()) {
                    for f in files.flatten() {
                        let p = f.path();
                        if p.extension().and_then(|s| s.to_str()) != Some("entry") {
                            continue;
                        }
                        if let Some(e) = fs::read(&p).ok().and_then(|b| Entry::decode(&b)) {
                            let mt = f
                                .metadata()
                                .and_then(|m| m.modified())
                                .unwrap_or(std::time::UNIX_EPOCH);
                            all.push((p, mt, e));
                        }
                    }
                }
            }
        }

        // Oldest first.
        all.sort_by_key(|x| x.1);

        let mut removed_entries = 0u64;
        let mut current = before;
        let mut surviving: Vec<Entry> = Vec::new();
        // Delete oldest until under budget. We approximate freed space by entry
        // file size; blob space is reclaimed in the sweep below.
        let mut idx = 0;
        while current > max_bytes && idx < all.len() {
            let (p, _, _e) = &all[idx];
            let sz = fs::metadata(p).map(|m| m.len()).unwrap_or(0);
            if fs::remove_file(p).is_ok() {
                removed_entries += 1;
                current = current.saturating_sub(sz);
            }
            idx += 1;
        }
        for (_, _, e) in all.into_iter().skip(idx) {
            surviving.push(e);
        }

        // Sweep unreferenced blobs.
        let mut referenced = std::collections::HashSet::new();
        for e in &surviving {
            referenced.insert(crate::hash_hex(&e.console));
            for o in &e.outputs {
                if let crate::fingerprint::FileState::File { content, .. } = &o.state {
                    referenced.insert(crate::hash_hex(content));
                }
            }
            for i in &e.inputs {
                if let crate::fingerprint::InputFp::File { hash: Some(h), .. } = &i.fp {
                    referenced.insert(crate::hash_hex(h));
                }
            }
        }

        let mut removed_blobs = 0u64;
        let cas = self.root.join("cas");
        if let Ok(shards) = fs::read_dir(&cas) {
            for shard in shards.flatten() {
                if !shard.path().is_dir() {
                    continue;
                }
                if let Ok(files) = fs::read_dir(shard.path()) {
                    for f in files.flatten() {
                        let name = f.file_name().to_string_lossy().into_owned();
                        if !referenced.contains(&name) && fs::remove_file(f.path()).is_ok() {
                            removed_blobs += 1;
                        }
                    }
                }
            }
        }

        let after = self.stats().total_bytes;
        Ok(GcReport {
            removed_entries,
            removed_blobs,
            freed_bytes: before.saturating_sub(after),
        })
    }
}

fn now_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

fn count_dir(dir: &Path, ext: &str) -> (u64, u64) {
    let mut n = 0u64;
    let mut bytes = 0u64;
    if let Ok(keys) = fs::read_dir(dir) {
        for key in keys.flatten() {
            if key.path().is_dir() {
                if let Ok(files) = fs::read_dir(key.path()) {
                    for f in files.flatten() {
                        if f.path().extension().and_then(|s| s.to_str()) == Some(ext) {
                            n += 1;
                            bytes += f.metadata().map(|m| m.len()).unwrap_or(0);
                        }
                    }
                }
            }
        }
    }
    (n, bytes)
}

fn count_all_files(dir: &Path) -> (u64, u64) {
    let mut n = 0u64;
    let mut bytes = 0u64;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        if let Ok(rd) = fs::read_dir(&d) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else {
                    n += 1;
                    bytes += e.metadata().map(|m| m.len()).unwrap_or(0);
                }
            }
        }
    }
    (n, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::Entry;

    fn mk_entry(tag: &str) -> Entry {
        Entry {
            format: crate::FORMAT_VERSION,
            argv: vec![tag.into()],
            cwd: "C:\\p".into(),
            created: 0,
            duration_ms: 10,
            exit_code: 0,
            inputs: vec![],
            outputs: vec![],
            console: [0; 32],
        }
    }

    #[test]
    fn put_then_load_returns_entry() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(dir.path());
        s.put_entry("k", &mk_entry("a")).unwrap();
        let got = s.load_entries("k");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].1.argv, vec!["a".to_string()]);
    }

    #[test]
    fn load_returns_newest_first() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(dir.path());
        s.put_entry("k", &mk_entry("old")).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        s.put_entry("k", &mk_entry("new")).unwrap();
        let got = s.load_entries("k");
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].1.argv, vec!["new".to_string()]);
    }

    #[test]
    fn corrupt_entry_is_skipped_and_removed() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(dir.path());
        let kd = s.key_dir("k");
        fs::create_dir_all(&kd).unwrap();
        fs::write(kd.join("bad.entry"), b"not postcard").unwrap();
        assert_eq!(s.load_entries("k").len(), 0);
        assert!(!kd.join("bad.entry").exists());
    }

    #[test]
    fn counters_accumulate() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(dir.path());
        s.record_hit(100);
        s.record_hit(50);
        s.record_store();
        let c = s.load_counters();
        assert_eq!(c.hits, 2);
        assert_eq!(c.saved_ms, 150);
        assert_eq!(c.stores, 1);
    }

    #[test]
    fn gc_evicts_and_sweeps_blobs() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(dir.path());
        let cas = s.cas();
        // A blob only referenced by an entry we will evict.
        let h = cas.put_bytes(b"orphan-to-be").unwrap();
        let mut e = mk_entry("old");
        e.outputs.push(crate::entry::Output {
            path: "C:\\p\\o".into(),
            state: crate::fingerprint::FileState::File {
                size: 12,
                mtime: 0,
                readonly: false,
                content: h,
            },
        });
        s.put_entry("k", &e).unwrap();

        assert!(cas.has(&h));
        // Force eviction of everything.
        let report = s.gc(0).unwrap();
        assert!(report.removed_entries >= 1);
        assert!(!cas.has(&h), "orphaned blob should be swept");
    }
}
