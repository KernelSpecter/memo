//! Core library for memo: paths, content store, stat cache, fingerprints,
//! cache entries, verification, and the on-disk store.

pub mod cas;
pub mod entry;
pub mod fingerprint;
pub mod paths;
pub mod stat;
pub mod statcache;
pub mod verify;

/// Cache format version; re-exported from the protocol crate so bumping it in
/// one place invalidates both wire and on-disk assumptions.
pub use memo_proto::FORMAT_VERSION;

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
