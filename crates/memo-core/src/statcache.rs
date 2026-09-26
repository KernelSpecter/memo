//! Persistent stat cache: maps a path's stat signature to the content hash we
//! computed for it, so verification re-hashes a file only when its signature
//! (size/mtime/change-time/file-id) changed.

use crate::paths::PathId;
use crate::stat::{file_signature, FileSig};
use crate::Hash;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Default, Serialize, Deserialize)]
struct CacheData {
    // PathId string -> (signature, hash)
    entries: HashMap<String, (FileSig, Hash)>,
}

pub struct StatCache {
    file: PathBuf,
    data: CacheData,
    dirty: bool,
    /// Count of real content hashes computed (for tests/telemetry).
    pub hashed: u64,
}

impl StatCache {
    pub fn load(file: impl AsRef<Path>) -> Self {
        let file = file.as_ref().to_path_buf();
        let data = std::fs::read(&file)
            .ok()
            .and_then(|bytes| postcard::from_bytes::<CacheData>(&bytes).ok())
            .unwrap_or_default();
        StatCache {
            file,
            data,
            dirty: false,
            hashed: 0,
        }
    }

    pub fn save(&mut self) -> io::Result<()> {
        if !self.dirty {
            return Ok(());
        }
        if let Some(parent) = self.file.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let bytes = postcard::to_stdvec(&self.data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        let tmp = self.file.with_extension("tmp");
        std::fs::write(&tmp, &bytes)?;
        std::fs::rename(&tmp, &self.file)?;
        self.dirty = false;
        Ok(())
    }

    /// Hash a file's content, reusing a cached hash if the stat signature is
    /// unchanged since we last hashed it.
    pub fn hash_of(&mut self, path: &Path) -> io::Result<Hash> {
        let id = PathId::new(&path.to_string_lossy()).0;
        let sig = file_signature(path)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no signature"))?;

        if let Some((cached_sig, cached_hash)) = self.data.entries.get(&id) {
            if *cached_sig == sig {
                return Ok(*cached_hash);
            }
        }

        let content = std::fs::read(path)?;
        let h: Hash = *blake3::hash(&content).as_bytes();
        self.hashed += 1;
        self.data.entries.insert(id, (sig, h));
        self.dirty = true;
        Ok(h)
    }
}

/// Hash a file's content using a shared, mutex-guarded stat cache, holding the
/// lock only for the cache lookup and insert (never during file I/O). Used by
/// parallel verification.
pub fn hash_of_shared(
    sc: &std::sync::Mutex<StatCache>,
    path: &Path,
) -> io::Result<Hash> {
    let id = PathId::new(&path.to_string_lossy()).0;
    let sig = file_signature(path)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no signature"))?;

    {
        let g = sc.lock().unwrap();
        if let Some((cached_sig, cached_hash)) = g.data.entries.get(&id) {
            if *cached_sig == sig {
                return Ok(*cached_hash);
            }
        }
    }

    let content = std::fs::read(path)?;
    let h: Hash = *blake3::hash(&content).as_bytes();

    {
        let mut g = sc.lock().unwrap();
        g.hashed += 1;
        g.data.entries.insert(id, (sig, h));
        g.dirty = true;
    }
    Ok(h)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reuses_hash_when_signature_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("a.txt");
        std::fs::write(&f, b"content").unwrap();
        let mut sc = StatCache::load(dir.path().join("statcache.bin"));

        let h1 = sc.hash_of(&f).unwrap();
        assert_eq!(sc.hashed, 1);
        let h2 = sc.hash_of(&f).unwrap();
        assert_eq!(sc.hashed, 1, "second call must not re-hash");
        assert_eq!(h1, h2);
    }

    #[test]
    fn rehashes_when_file_changes() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("a.txt");
        std::fs::write(&f, b"one").unwrap();
        let mut sc = StatCache::load(dir.path().join("statcache.bin"));
        let h1 = sc.hash_of(&f).unwrap();

        // Ensure a distinct write time, then change content.
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&f, b"two-different").unwrap();

        let h2 = sc.hash_of(&f).unwrap();
        assert_eq!(sc.hashed, 2, "changed file must re-hash");
        assert_ne!(h1, h2);
    }

    #[test]
    fn persists_across_load() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("a.txt");
        std::fs::write(&f, b"persist").unwrap();
        let cache_file = dir.path().join("statcache.bin");

        let mut sc = StatCache::load(&cache_file);
        let h1 = sc.hash_of(&f).unwrap();
        sc.save().unwrap();

        let mut sc2 = StatCache::load(&cache_file);
        let h2 = sc2.hash_of(&f).unwrap();
        assert_eq!(sc2.hashed, 0, "loaded cache must reuse stored hash");
        assert_eq!(h1, h2);
    }
}
