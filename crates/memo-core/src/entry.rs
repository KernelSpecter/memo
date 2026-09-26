//! The cache entry: the record of one traced run — its inputs' fingerprints,
//! its outputs' final states, and the console output — keyed by the command.

use crate::fingerprint::{FileState, InputFp};
use crate::Hash;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Input {
    pub path: String,
    pub fp: InputFp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Output {
    pub path: String,
    pub state: FileState,
}

/// A complete record of one cacheable run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub format: u32,
    pub argv: Vec<String>,
    pub cwd: String,
    /// Unix-ish creation timestamp (secs) for LRU / display.
    pub created: i64,
    pub duration_ms: u64,
    pub exit_code: i32,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    /// Content hash of the serialized console chunk log.
    pub console: Hash,
}

impl Entry {
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("entry encodes")
    }

    pub fn decode(bytes: &[u8]) -> Option<Entry> {
        postcard::from_bytes(bytes).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_round_trips() {
        let e = Entry {
            format: crate::FORMAT_VERSION,
            argv: vec!["npm".into(), "test".into()],
            cwd: "C:\\proj".into(),
            created: 1_700_000_000,
            duration_ms: 41200,
            exit_code: 0,
            inputs: vec![
                Input {
                    path: "C:\\proj\\a.txt".into(),
                    fp: InputFp::File {
                        size: 3,
                        mtime: Some(10),
                        hash: Some([7; 32]),
                    },
                },
                Input {
                    path: "C:\\proj\\missing".into(),
                    fp: InputFp::Absent,
                },
            ],
            outputs: vec![Output {
                path: "C:\\proj\\out.js".into(),
                state: FileState::File {
                    size: 5,
                    mtime: 20,
                    readonly: false,
                    content: [9; 32],
                },
            }],
            console: [1; 32],
        };
        let bytes = e.encode();
        let back = Entry::decode(&bytes).unwrap();
        assert_eq!(back, e);
    }

    #[test]
    fn decode_garbage_is_none() {
        assert!(Entry::decode(&[0xff, 0xff, 0xff]).is_none());
    }
}
