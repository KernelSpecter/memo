//! Verification: does an entry's recorded input set still match the current
//! filesystem? If every input matches, the run can be replayed.

use crate::entry::{Entry, Input};
use crate::fingerprint::{read_dir_entries, recompute_listing_hash, InputFp};
use crate::stat::{file_signature, FType};
use crate::statcache::{hash_of_shared, StatCache};
use rayon::prelude::*;
use std::path::Path;
use std::sync::Mutex;

/// Verify a single input against the current filesystem state.
pub fn verify_input(inp: &Input, sc: &Mutex<StatCache>) -> bool {
    let path = Path::new(&inp.path);
    match &inp.fp {
        InputFp::Absent => file_signature(path).is_none(),

        InputFp::Dir { listing } => {
            let sig = match file_signature(path) {
                Some(s) => s,
                None => return false,
            };
            if sig.ftype != FType::Dir {
                return false;
            }
            match listing {
                None => true,
                Some(lfp) => match read_dir_entries(path) {
                    Ok(entries) => recompute_listing_hash(&entries, &lfp.stripped) == lfp.hash,
                    Err(_) => false,
                },
            }
        }

        InputFp::File { size, mtime, hash } => {
            let sig = match file_signature(path) {
                Some(s) => s,
                None => return false,
            };
            if sig.ftype != FType::File {
                return false;
            }
            if sig.size != *size {
                return false;
            }
            if let Some(mt) = mtime {
                if sig.mtime != *mt {
                    return false;
                }
            }
            if let Some(expected) = hash {
                match hash_of_shared(sc, path) {
                    Ok(h) => &h == expected,
                    Err(_) => false,
                }
            } else {
                true
            }
        }
    }
}

/// Verify a whole entry: all inputs must match. Parallel with short-circuit.
pub fn verify_entry(e: &Entry, sc: &Mutex<StatCache>) -> bool {
    e.inputs.par_iter().all(|inp| verify_input(inp, sc))
}

/// Find the first input that does not match, for `memo explain`.
pub fn first_mismatch<'a>(e: &'a Entry, sc: &Mutex<StatCache>) -> Option<&'a Input> {
    e.inputs.iter().find(|inp| !verify_input(inp, sc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::Input;
    use crate::fingerprint::{build_input_fp, compute_listing_fp, PreState};
    use crate::statcache::StatCache;
    use std::collections::HashSet;
    use std::fs;

    fn sc(dir: &Path) -> Mutex<StatCache> {
        Mutex::new(StatCache::load(dir.join("statcache.bin")))
    }

    fn file_input(path: &Path, sc: &Mutex<StatCache>) -> Input {
        let sig = file_signature(path).unwrap();
        let hash = hash_of_shared(sc, path).unwrap();
        Input {
            path: path.to_string_lossy().into_owned(),
            fp: build_input_fp(
                PreState::File {
                    size: sig.size,
                    mtime: Some(sig.mtime),
                    hash: Some(hash),
                },
                false,
            ),
        }
    }

    #[test]
    fn matching_file_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("a.txt");
        fs::write(&f, b"hello").unwrap();
        let sc = sc(dir.path());
        let inp = file_input(&f, &sc);
        assert!(verify_input(&inp, &sc));
    }

    #[test]
    fn changed_content_fails() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("a.txt");
        fs::write(&f, b"hello").unwrap();
        let sc = sc(dir.path());
        let inp = file_input(&f, &sc);

        std::thread::sleep(std::time::Duration::from_millis(20));
        fs::write(&f, b"changed!!").unwrap();
        assert!(!verify_input(&inp, &sc));
    }

    #[test]
    fn absent_input_matches_only_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("ghost");
        let sc = sc(dir.path());
        let inp = Input {
            path: p.to_string_lossy().into_owned(),
            fp: InputFp::Absent,
        };
        assert!(verify_input(&inp, &sc), "absent path matches Absent");

        fs::write(&p, b"now here").unwrap();
        assert!(!verify_input(&inp, &sc), "creating it must fail the match");
    }

    #[test]
    fn new_file_in_listed_dir_fails() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("d");
        fs::create_dir(&sub).unwrap();
        fs::write(sub.join("a.txt"), b"a").unwrap();
        let sc = sc(dir.path());

        let entries = read_dir_entries(&sub).unwrap();
        let lfp = compute_listing_fp(&entries, &HashSet::new());
        let inp = Input {
            path: sub.to_string_lossy().into_owned(),
            fp: InputFp::Dir { listing: Some(lfp) },
        };
        assert!(verify_input(&inp, &sc));

        // An external file appears.
        fs::write(sub.join("intruder.txt"), b"x").unwrap();
        assert!(!verify_input(&inp, &sc));
    }

    #[test]
    fn mutated_output_mtime_change_still_matches() {
        // A path the command mutated: mtime is dropped from the fingerprint, so
        // a new mtime (from the command's own rewrite) must not fail the match.
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("out.bin");
        fs::write(&f, b"stable").unwrap();
        let sc = sc(dir.path());
        let sig = file_signature(&f).unwrap();
        let hash = hash_of_shared(&sc, &f).unwrap();
        let inp = Input {
            path: f.to_string_lossy().into_owned(),
            fp: build_input_fp(
                PreState::File {
                    size: sig.size,
                    mtime: Some(sig.mtime),
                    hash: Some(hash),
                },
                true, // mutated
            ),
        };

        // Rewrite identical content with a new mtime.
        std::thread::sleep(std::time::Duration::from_millis(20));
        fs::write(&f, b"stable").unwrap();
        assert!(
            verify_input(&inp, &sc),
            "identical content with new mtime must still match when mutated"
        );
    }

    #[test]
    fn verify_entry_all_inputs() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        fs::write(&a, b"aaa").unwrap();
        fs::write(&b, b"bbb").unwrap();
        let sc = sc(dir.path());
        let e = Entry {
            format: crate::FORMAT_VERSION,
            argv: vec!["x".into()],
            cwd: dir.path().to_string_lossy().into_owned(),
            created: 0,
            duration_ms: 0,
            exit_code: 0,
            inputs: vec![file_input(&a, &sc), file_input(&b, &sc)],
            outputs: vec![],
            console: [0; 32],
        };
        assert!(verify_entry(&e, &sc));

        std::thread::sleep(std::time::Duration::from_millis(20));
        fs::write(&b, b"different").unwrap();
        assert!(!verify_entry(&e, &sc));
        assert_eq!(
            first_mismatch(&e, &sc).map(|i| i.path.clone()),
            Some(b.to_string_lossy().into_owned())
        );
    }
}
