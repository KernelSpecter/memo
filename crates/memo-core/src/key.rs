//! Cache key computation. The key identifies "the same command in the same
//! place with the same inputs-determining context": normalized cwd, argv, the
//! full environment, and the resolved program's own content hash.

use crate::paths::normalize;
use crate::{hash_hex, Hash};
use std::collections::BTreeMap;

/// Compute the cache key. `env` is the child's full environment (see the design
/// ruling: v1 includes all variables; color-forcing vars are intentionally part
/// of the key so console and redirected runs cache separately).
pub fn compute_key(
    cwd: &str,
    argv: &[String],
    env: &BTreeMap<String, String>,
    app_hash: &Hash,
) -> String {
    let mut h = blake3::Hasher::new();
    h.update(&crate::FORMAT_VERSION.to_le_bytes());

    let ncwd = normalize(cwd).to_lowercase();
    h.update(b"cwd\0");
    h.update(ncwd.as_bytes());

    h.update(b"\0argv\0");
    for a in argv {
        h.update(&(a.len() as u64).to_le_bytes());
        h.update(a.as_bytes());
    }

    h.update(b"\0env\0");
    for (k, v) in env {
        h.update(&(k.len() as u64).to_le_bytes());
        h.update(k.as_bytes());
        h.update(&(v.len() as u64).to_le_bytes());
        h.update(v.as_bytes());
    }

    h.update(b"\0app\0");
    h.update(app_hash);

    hash_hex(h.finalize().as_bytes())
}

/// Stable hash of (cwd, argv) only — identifies a command regardless of env, so
/// `explain` can find the last run and diff the environment.
pub fn run_slot(cwd: &str, argv: &[String]) -> String {
    let mut h = blake3::Hasher::new();
    h.update(normalize(cwd).to_lowercase().as_bytes());
    for a in argv {
        h.update(&[0]);
        h.update(a.as_bytes());
    }
    hash_hex(h.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        m.insert("PATH".into(), "C:\\bin".into());
        m
    }

    #[test]
    fn same_inputs_same_key() {
        let a = compute_key("C:\\p", &["x".into()], &env(), &[1; 32]);
        let b = compute_key("C:\\p", &["x".into()], &env(), &[1; 32]);
        assert_eq!(a, b);
    }

    #[test]
    fn cwd_is_case_and_slash_insensitive() {
        let a = compute_key("C:\\Proj", &["x".into()], &env(), &[1; 32]);
        let b = compute_key("c:/proj", &["x".into()], &env(), &[1; 32]);
        assert_eq!(a, b);
    }

    #[test]
    fn different_argv_different_key() {
        let a = compute_key("C:\\p", &["x".into()], &env(), &[1; 32]);
        let b = compute_key("C:\\p", &["y".into()], &env(), &[1; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn different_env_different_key() {
        let mut e2 = env();
        e2.insert("FORCE_COLOR".into(), "1".into());
        let a = compute_key("C:\\p", &["x".into()], &env(), &[1; 32]);
        let b = compute_key("C:\\p", &["x".into()], &e2, &[1; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn different_app_hash_different_key() {
        let a = compute_key("C:\\p", &["x".into()], &env(), &[1; 32]);
        let b = compute_key("C:\\p", &["x".into()], &env(), &[2; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn run_slot_ignores_env() {
        assert_eq!(
            run_slot("C:\\p", &["x".into()]),
            run_slot("C:\\p", &["x".into()])
        );
    }
}
