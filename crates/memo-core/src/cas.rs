//! Content-addressed store. Blobs are keyed by their BLAKE3 hash and stored
//! under `cas/<aa>/<full-hex>`, so identical content is stored once.

use crate::{hash_hex, Hash};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

pub struct Store {
    root: PathBuf,
}

impl Store {
    pub fn new(root: impl AsRef<Path>) -> Self {
        Store {
            root: root.as_ref().to_path_buf(),
        }
    }

    fn path_for(&self, h: &Hash) -> PathBuf {
        let hex = hash_hex(h);
        self.root.join(&hex[..2]).join(&hex)
    }

    /// Public path where a blob lives (may not exist yet).
    pub fn get_path(&self, h: &Hash) -> PathBuf {
        self.path_for(h)
    }

    pub fn has(&self, h: &Hash) -> bool {
        self.path_for(h).exists()
    }

    /// Store bytes; returns the content hash. Idempotent.
    pub fn put_bytes(&self, bytes: &[u8]) -> io::Result<Hash> {
        let h: Hash = *blake3::hash(bytes).as_bytes();
        let dest = self.path_for(&h);
        if dest.exists() {
            return Ok(h);
        }
        fs::create_dir_all(dest.parent().unwrap())?;
        write_atomic(&dest, bytes)?;
        Ok(h)
    }

    /// Store a file's contents; returns the content hash.
    pub fn put_file(&self, src: &Path) -> io::Result<Hash> {
        let mut f = fs::File::open(src)?;
        let mut hasher = blake3::Hasher::new();
        let mut buf = vec![0u8; 128 * 1024];
        let mut all = Vec::new();
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            all.extend_from_slice(&buf[..n]);
        }
        let h: Hash = *hasher.finalize().as_bytes();
        let dest = self.path_for(&h);
        if !dest.exists() {
            fs::create_dir_all(dest.parent().unwrap())?;
            write_atomic(&dest, &all)?;
        }
        Ok(h)
    }

    pub fn open(&self, h: &Hash) -> io::Result<fs::File> {
        fs::File::open(self.path_for(h))
    }

    pub fn read(&self, h: &Hash) -> io::Result<Vec<u8>> {
        fs::read(self.path_for(h))
    }
}

/// Write to a sibling temp file then rename over the destination.
fn write_atomic(dest: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = dest.with_extension(format!("tmp-{}", std::process::id()));
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    // Rename is atomic on the same volume; if dest appeared meanwhile (another
    // process stored the same content), that's fine — content is identical.
    match fs::rename(&tmp, dest) {
        Ok(()) => Ok(()),
        Err(_) if dest.exists() => {
            let _ = fs::remove_file(&tmp);
            Ok(())
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_and_read_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path());
        let h = store.put_bytes(b"hello world").unwrap();
        assert_eq!(store.read(&h).unwrap(), b"hello world");
    }

    #[test]
    fn identical_content_same_hash_and_path() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path());
        let h1 = store.put_bytes(b"same").unwrap();
        let h2 = store.put_bytes(b"same").unwrap();
        assert_eq!(h1, h2);
        assert_eq!(store.get_path(&h1), store.get_path(&h2));
    }

    #[test]
    fn put_file_matches_put_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path());
        let src = dir.path().join("src.bin");
        std::fs::write(&src, b"file content").unwrap();
        let hf = store.put_file(&src).unwrap();
        let hb = store.put_bytes(b"file content").unwrap();
        assert_eq!(hf, hb);
    }
}
