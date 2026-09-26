//! Core library for memo: paths, content store, stat cache, fingerprints,
//! cache entries, verification, and the on-disk store.

pub mod cas;
pub mod paths;
pub mod stat;
pub mod statcache;

/// A 32-byte BLAKE3 content hash.
pub type Hash = [u8; 32];

/// Hex-encode a hash.
pub fn hash_hex(h: &Hash) -> String {
    let mut s = String::with_capacity(64);
    for b in h {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
