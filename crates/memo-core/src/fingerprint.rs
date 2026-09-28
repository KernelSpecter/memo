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

/// Fingerprint of a directory listing as the command saw it at the moment it
/// first enumerated the directory (spec §6.2). The hash covers every entry;
/// entries the tree itself mutated contribute only `(name, is_dir)` — not their
/// volatile size/mtime — since the tree rewrites its own outputs each run and
/// those bytes are pinned separately (as outputs). `name_only` records which
/// case-folded names got that treatment, so verification recomputes identically.
///
/// This is what makes a list-then-write converge in two runs: run 1 enumerates
/// before creating its output (the output is absent from the snapshot), so run 2
/// — where the output now exists — sees a different listing and re-executes;
/// run 2's snapshot includes the output by name only, so run 3 matches and
/// replays despite the output's mtime changing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListingFp {
    pub hash: Hash,
    pub name_only: Vec<String>,
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

/// Compute a listing fingerprint over a directory's pre-run entries. Entries
/// whose case-folded name is in `name_only` (the tree's own mutated outputs)
/// contribute only `(name, is_dir)`; all others contribute size and mtime too.
pub fn compute_listing_fp(entries: &[DirEntry], name_only: &HashSet<String>) -> ListingFp {
    ListingFp {
        hash: hash_entries(entries, name_only),
        name_only: name_only.iter().cloned().collect(),
    }
}

/// Recompute a listing hash from current entries, giving the recorded
/// `name_only` names the same name-only treatment. Matches `compute_listing_fp`'s
/// hash iff the directory's entries are unchanged (mutated entries aside).
pub fn recompute_listing_hash(entries: &[DirEntry], name_only: &[String]) -> Hash {
    let set: HashSet<String> = name_only.iter().cloned().collect();
    hash_entries(entries, &set)
}

fn hash_entries(entries: &[DirEntry], name_only: &HashSet<String>) -> Hash {
    // Sort by case-folded name for order independence.
    let mut rows: Vec<(String, &DirEntry)> =
        entries.iter().map(|e| (case_fold(&e.name), e)).collect();
    rows.sort_by(|a, b| a.0.cmp(&b.0));

    let mut hasher = blake3::Hasher::new();
    for (folded, e) in rows {
        hasher.update(folded.as_bytes());
        hasher.update(&[0]);
        hasher.update(&[e.is_dir as u8]);
        // A mutated entry contributes name + is_dir only: its size/mtime are the
        // tree's own output, volatile run-to-run and pinned elsewhere.
        if !name_only.contains(&folded) {
            hasher.update(&e.size.to_le_bytes());
            hasher.update(&e.mtime.to_le_bytes());
        }
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
    fn new_entry_changes_the_hash() {
        // A file appearing changes the listing — whoever created it. The command
        // saw the pre-write listing, so on the next run (entry now present) the
        // run must re-execute, not replay (spec §6.2).
        let pre = vec![DirEntry {
            name: "a.txt".into(),
            is_dir: false,
            size: 1,
            mtime: 10,
        }];
        let fp = compute_listing_fp(&pre, &HashSet::new());
        let after = vec![
            pre[0].clone(),
            DirEntry {
                name: "out.js".into(),
                is_dir: false,
                size: 99,
                mtime: 55,
            },
        ];
        assert_ne!(
            fp.hash,
            recompute_listing_hash(&after, &fp.name_only),
            "a new entry must change the listing hash"
        );
    }

    #[test]
    fn name_only_entry_ignores_size_and_mtime() {
        // The tree's own output in a listed dir contributes name+is_dir only, so
        // its changing size/mtime across runs does not destabilize the listing
        // (this is what lets a list-then-write converge to a replay).
        let mut name_only = HashSet::new();
        name_only.insert("out.js".to_string());
        let run2 = vec![
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
        let fp = compute_listing_fp(&run2, &name_only);
        // Next run: out.js rewritten (new size + mtime), a.txt unchanged.
        let run3 = vec![
            DirEntry {
                name: "a.txt".into(),
                is_dir: false,
                size: 1,
                mtime: 10,
            },
            DirEntry {
                name: "out.js".into(),
                is_dir: false,
                size: 123,
                mtime: 999,
            },
        ];
        assert_eq!(
            fp.hash,
            recompute_listing_hash(&run3, &fp.name_only),
            "a mutated entry's size/mtime must not affect the listing hash"
        );
        // But a.txt changing size does change it.
        let run3b = vec![
            DirEntry {
                name: "a.txt".into(),
                is_dir: false,
                size: 2,
                mtime: 10,
            },
            DirEntry {
                name: "out.js".into(),
                is_dir: false,
                size: 123,
                mtime: 999,
            },
        ];
        assert_ne!(fp.hash, recompute_listing_hash(&run3b, &fp.name_only));
    }
}
