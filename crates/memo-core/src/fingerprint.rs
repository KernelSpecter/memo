//! Fingerprints: how memo captures the pre-run state of every input and the
//! final state of every output, and how it decides what must match on replay.

use crate::paths::case_fold;
use crate::Hash;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// The final (post-run) state of a path, used to restore outputs on replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileState {
    Absent,
    Dir,
    File {
        size: u64,
        mtime: i64,
        readonly: bool,
        content: Hash,
    },
}

/// The fingerprint of an input: the pre-run state the command depended on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InputFp {
    /// Path did not exist.
    Absent,
    /// Path was a directory. `listing` present iff the command enumerated it.
    Dir { listing: Option<ListingFp> },
    /// Path was a file. `hash` present iff read; `mtime` present iff metadata
    /// was observed and the path was not itself mutated by the tree.
    File {
        size: u64,
        mtime: Option<i64>,
        hash: Option<Hash>,
    },
}

/// Fingerprint of a directory listing: a hash over its non-mutated entries,
/// plus the case-folded names excluded (the command's own outputs), so
/// verification recomputes the same hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListingFp {
    pub hash: Hash,
    pub stripped: Vec<String>,
}

/// One entry in a directory listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub mtime: i64,
}

/// Enumerate a directory into canonical [`DirEntry`] rows. Used by both the run
/// engine (to snapshot pre-run listings) and verification, so their hashes
/// agree. Errors (e.g. path is not a directory) propagate.
pub fn read_dir_entries(dir: &std::path::Path) -> std::io::Result<Vec<DirEntry>> {
    #[cfg(windows)]
    use std::os::windows::fs::MetadataExt;

    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        // Use symlink_metadata so a symlink is described as itself, not target.
        let md = entry.metadata()?;
        let is_dir = md.is_dir();
        #[cfg(windows)]
        let (size, mtime) = (md.file_size(), md.last_write_time() as i64);
        #[cfg(not(windows))]
        let (size, mtime) = (md.len(), 0i64);
        out.push(DirEntry {
            name,
            is_dir,
            size,
            mtime,
        });
    }
    Ok(out)
}

/// The pre-run observed state of a path, gathered during the run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreState {
    Absent,
    /// `listing` present iff the directory was enumerated.
    Dir {
        listing: Option<ListingFp>,
    },
    /// `mtime`/`hash` are `Some` iff metadata / content were observed.
    File {
        size: u64,
        mtime: Option<i64>,
        hash: Option<Hash>,
    },
}

/// Build an input fingerprint from the pre-run state, dropping mtime if the
/// tree mutated the path (its new content is the command's own output).
pub fn build_input_fp(pre: PreState, mutated: bool) -> InputFp {
    match pre {
        PreState::Absent => InputFp::Absent,
        PreState::Dir { listing } => InputFp::Dir { listing },
        PreState::File { size, mtime, hash } => InputFp::File {
            size,
            mtime: if mutated { None } else { mtime },
            hash,
        },
    }
}

/// Compute a listing fingerprint over a directory's pre-run entries, excluding
/// any entry the tree mutated (matched by case-folded name).
pub fn compute_listing_fp(entries: &[DirEntry], mutated_names: &HashSet<String>) -> ListingFp {
    let stripped: Vec<String> = mutated_names.iter().cloned().collect();
    let hash = hash_entries(entries, mutated_names);
    ListingFp { hash, stripped }
}

/// Recompute a listing hash from current entries, excluding the recorded
/// `stripped` names. Must match `compute_listing_fp`'s hash when nothing
/// external changed.
pub fn recompute_listing_hash(entries: &[DirEntry], stripped: &[String]) -> Hash {
    let set: HashSet<String> = stripped.iter().cloned().collect();
    hash_entries(entries, &set)
}

fn hash_entries(entries: &[DirEntry], exclude: &HashSet<String>) -> Hash {
    // Sort by case-folded name for order independence; exclude mutated names.
    let mut rows: Vec<(String, &DirEntry)> = entries
        .iter()
        .map(|e| (case_fold(&e.name), e))
        .filter(|(folded, _)| !exclude.contains(folded))
        .collect();
    rows.sort_by(|a, b| a.0.cmp(&b.0));

    let mut hasher = blake3::Hasher::new();
    for (folded, e) in rows {
        hasher.update(folded.as_bytes());
        hasher.update(&[0]);
        hasher.update(&[e.is_dir as u8]);
        hasher.update(&e.size.to_le_bytes());
        hasher.update(&e.mtime.to_le_bytes());
        hasher.update(&[0xff]);
    }
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(byte: u8) -> Hash {
        [byte; 32]
    }

    #[test]
    fn read_file_gets_hash() {
        let fp = build_input_fp(
            PreState::File {
                size: 10,
                mtime: Some(123),
                hash: Some(h(1)),
            },
            false,
        );
        assert_eq!(
            fp,
            InputFp::File {
                size: 10,
                mtime: Some(123),
                hash: Some(h(1))
            }
        );
    }

    #[test]
    fn meta_only_unmutated_keeps_mtime_no_hash() {
        let fp = build_input_fp(
            PreState::File {
                size: 10,
                mtime: Some(123),
                hash: None,
            },
            false,
        );
        assert_eq!(
            fp,
            InputFp::File {
                size: 10,
                mtime: Some(123),
                hash: None
            }
        );
    }

    #[test]
    fn mutated_path_drops_mtime_keeps_size_and_content() {
        // Read-then-write: content matters, mtime must be dropped.
        let fp = build_input_fp(
            PreState::File {
                size: 10,
                mtime: Some(123),
                hash: Some(h(2)),
            },
            true,
        );
        assert_eq!(
            fp,
            InputFp::File {
                size: 10,
                mtime: None,
                hash: Some(h(2))
            }
        );
    }

    #[test]
    fn absent_maps_to_absent() {
        assert_eq!(build_input_fp(PreState::Absent, false), InputFp::Absent);
    }

    fn entries() -> Vec<DirEntry> {
        vec![
            DirEntry {
                name: "b.txt".into(),
                is_dir: false,
                size: 2,
                mtime: 20,
            },
            DirEntry {
                name: "a.txt".into(),
                is_dir: false,
                size: 1,
                mtime: 10,
            },
            DirEntry {
                name: "sub".into(),
                is_dir: true,
                size: 0,
                mtime: 5,
            },
        ]
    }

    #[test]
    fn listing_is_order_independent() {
        let mut e1 = entries();
        let mut e2 = e1.clone();
        e2.reverse();
        let none = HashSet::new();
        assert_eq!(hash_entries(&e1, &none), hash_entries(&e2, &none));
        e1.rotate_left(1);
        assert_eq!(hash_entries(&e1, &none), hash_entries(&e2, &none));
    }

    #[test]
    fn listing_excludes_mutated_entries() {
        // Directory that a command lists, then creates out.js into.
        let pre = vec![DirEntry {
            name: "a.txt".into(),
            is_dir: false,
            size: 1,
            mtime: 10,
        }];
        let mut mutated = HashSet::new();
        mutated.insert("out.js".to_string());
        let fp = compute_listing_fp(&pre, &mutated);

        // On the next run the directory also contains out.js (left by run 1).
        let after = vec![
            DirEntry {
                name: "a.txt".into(),
                is_dir: false,
                size: 1,
                mtime: 10,
            },
            DirEntry {
                name: "out.js".into(),
                is_dir: false,
                size: 99,
                mtime: 55,
            },
        ];
        let recomputed = recompute_listing_hash(&after, &fp.stripped);
        assert_eq!(
            fp.hash, recomputed,
            "the command's own output must not disturb the listing"
        );
    }

    #[test]
    fn listing_detects_external_new_file() {
        let pre = vec![DirEntry {
            name: "a.txt".into(),
            is_dir: false,
            size: 1,
            mtime: 10,
        }];
        let fp = compute_listing_fp(&pre, &HashSet::new());
        // An unrelated file appears (not one of the command's outputs).
        let after = vec![
            DirEntry {
                name: "a.txt".into(),
                is_dir: false,
                size: 1,
                mtime: 10,
            },
            DirEntry {
                name: "intruder".into(),
                is_dir: false,
                size: 3,
                mtime: 30,
            },
        ];
        let recomputed = recompute_listing_hash(&after, &fp.stripped);
        assert_ne!(fp.hash, recomputed);
    }
}
