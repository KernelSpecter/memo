//! Wire protocol shared between `memo.exe` (the tracer) and `memo_hook.dll`
//! (injected into every traced process). Messages are framed with a 4-byte
//! little-endian length prefix followed by a postcard-encoded [`Msg`].

use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

/// Cache format version. Bumping invalidates all stored entries and any
/// in-flight protocol assumptions.
pub const FORMAT_VERSION: u32 = 1;

/// Fixed-size POD payload copied into a target process via
/// `DetourCopyPayloadToProcess`. Tells the hook which pipe to connect to.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RunPayload {
    /// NUL-terminated UTF-16 pipe name, e.g. `\\.\pipe\memo-<id>`.
    pub pipe_name: [u16; 128],
    pub run_id: u64,
}

impl RunPayload {
    pub fn new(pipe_name: &str, run_id: u64) -> Self {
        let mut name = [0u16; 128];
        for (i, c) in pipe_name.encode_utf16().take(127).enumerate() {
            name[i] = c;
        }
        RunPayload {
            pipe_name: name,
            run_id,
        }
    }

    /// View the payload as raw bytes for `DetourCopyPayloadToProcess`.
    pub fn as_bytes(&self) -> &[u8] {
        // Safe: RunPayload is #[repr(C)] POD with no padding-sensitive reads.
        unsafe {
            core::slice::from_raw_parts(
                self as *const RunPayload as *const u8,
                core::mem::size_of::<RunPayload>(),
            )
        }
    }

    /// Reconstruct from a byte slice produced by [`as_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Option<RunPayload> {
        if bytes.len() != core::mem::size_of::<RunPayload>() {
            return None;
        }
        let mut p = RunPayload {
            pipe_name: [0u16; 128],
            run_id: 0,
        };
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                &mut p as *mut RunPayload as *mut u8,
                core::mem::size_of::<RunPayload>(),
            );
        }
        Some(p)
    }

    /// Decode the pipe name to a Rust string (stops at the first NUL).
    pub fn pipe_name_string(&self) -> String {
        let len = self
            .pipe_name
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(self.pipe_name.len());
        String::from_utf16_lossy(&self.pipe_name[..len])
    }
}

/// A path access that may make the run depend on that path's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessKind {
    /// Opened for reading (content matters).
    Read,
    /// Existence/metadata queried, or opened metadata-only, and it exists.
    Probe,
    /// Existence/metadata queried and it does NOT exist.
    ProbeAbsent,
    /// Directory contents enumerated.
    List,
}

/// A path mutation that may make the run produce that path as an output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MutateKind {
    Write,
    Create,
    Delete,
    Rename,
    SetMeta,
    MkDir,
}

/// Why a run cannot be cached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaintReason {
    Network,
    ReparsePoint,
    OpenById,
    Wow64Child,
    InjectFailed,
    HookInstallFailed,
    NoHello,
    ExternalModification,
    Outlived,
    Interrupted,
    NonZeroExit,
    InternalError,
}

impl TaintReason {
    pub fn human(&self) -> &'static str {
        match self {
            TaintReason::Network => "network access",
            TaintReason::ReparsePoint => "created/deleted a symlink or junction",
            TaintReason::OpenById => "opened a file by ID (path unknown)",
            TaintReason::Wow64Child => "spawned a 32-bit child process",
            TaintReason::InjectFailed => "could not inject into a child process",
            TaintReason::HookInstallFailed => "could not install hooks",
            TaintReason::NoHello => "a child process never checked in",
            TaintReason::ExternalModification => "an input changed during the run",
            TaintReason::Outlived => "a process outlived the command (daemon)",
            TaintReason::Interrupted => "the command was interrupted",
            TaintReason::NonZeroExit => "the command exited non-zero",
            TaintReason::InternalError => "an internal memo error",
        }
    }
}

/// A single message from a hooked process to `memo.exe`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Msg {
    Hello {
        pid: u32,
        ppid: u32,
        image: String,
        loaded_modules: Vec<String>,
    },
    Access {
        pid: u32,
        kind: AccessKind,
        path: String,
    },
    PreMutate {
        pid: u32,
        seq: u64,
        path: String,
    },
    Mutate {
        pid: u32,
        kind: MutateKind,
        path: String,
        target: Option<String>,
    },
    Taint {
        pid: u32,
        reason: TaintReason,
        detail: String,
    },
    ChildSpawned {
        pid: u32,
        child_pid: u32,
        injected: bool,
    },
    Bye {
        pid: u32,
        exit_ok: bool,
    },
}

/// The single acknowledgement byte memo writes back after snapshotting a
/// `PreMutate`. The hook blocks until it reads this.
pub const ACK: u8 = 1;

/// Maximum accepted frame length (guards against a corrupt length prefix).
const MAX_FRAME: u32 = 8 * 1024 * 1024;

/// Write one length-prefixed, postcard-encoded message.
pub fn write_msg<W: Write>(w: &mut W, msg: &Msg) -> io::Result<()> {
    let body = postcard::to_stdvec(msg)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let len = body.len() as u32;
    w.write_all(&len.to_le_bytes())?;
    w.write_all(&body)?;
    Ok(())
}

/// Read one message. Returns `Ok(None)` cleanly at end of stream (no partial
/// frame). A partial frame after some bytes is an error.
pub fn read_msg<R: Read>(r: &mut R) -> io::Result<Option<Msg>> {
    let mut len_buf = [0u8; 4];
    match read_exact_or_eof(r, &mut len_buf)? {
        ReadState::Eof => return Ok(None),
        ReadState::Full => {}
    }
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body)?;
    let msg = postcard::from_bytes(&body)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    Ok(Some(msg))
}

enum ReadState {
    Eof,
    Full,
}

/// Read exactly `buf.len()` bytes, but report a clean EOF if the very first
/// read returns 0 bytes (stream ended on a frame boundary).
fn read_exact_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<ReadState> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => {
                if filled == 0 {
                    return Ok(ReadState::Eof);
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "partial length prefix",
                ));
            }
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(ReadState::Full)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_msgs() -> Vec<Msg> {
        vec![
            Msg::Hello {
                pid: 42,
                ppid: 7,
                image: "C:\\node.exe".into(),
                loaded_modules: vec!["ntdll.dll".into(), "kernel32.dll".into()],
            },
            Msg::Access {
                pid: 42,
                kind: AccessKind::Read,
                path: "C:\\proj\\src\\main.rs".into(),
            },
            Msg::Access {
                pid: 42,
                kind: AccessKind::ProbeAbsent,
                path: "C:\\proj\\missing".into(),
            },
            Msg::PreMutate {
                pid: 42,
                seq: 1,
                path: "C:\\proj\\out.js".into(),
            },
            Msg::Mutate {
                pid: 42,
                kind: MutateKind::Rename,
                path: "C:\\proj\\tmp".into(),
                target: Some("C:\\proj\\final".into()),
            },
            Msg::Taint {
                pid: 42,
                reason: TaintReason::Network,
                detail: "connect 1.2.3.4:443".into(),
            },
            Msg::ChildSpawned {
                pid: 42,
                child_pid: 99,
                injected: true,
            },
            Msg::Bye {
                pid: 42,
                exit_ok: true,
            },
        ]
    }

    #[test]
    fn every_msg_round_trips() {
        for m in sample_msgs() {
            let mut buf = Vec::new();
            write_msg(&mut buf, &m).unwrap();
            let mut cur = std::io::Cursor::new(buf);
            let got = read_msg(&mut cur).unwrap().expect("one message");
            assert_eq!(got, m);
        }
    }

    #[test]
    fn multiple_msgs_stream_in_order() {
        let msgs = sample_msgs();
        let mut buf = Vec::new();
        for m in &msgs {
            write_msg(&mut buf, m).unwrap();
        }
        let mut cur = std::io::Cursor::new(buf);
        let mut got = Vec::new();
        while let Some(m) = read_msg(&mut cur).unwrap() {
            got.push(m);
        }
        assert_eq!(got, msgs);
    }

    #[test]
    fn read_from_empty_returns_none() {
        let mut cur = std::io::Cursor::new(Vec::<u8>::new());
        assert!(read_msg(&mut cur).unwrap().is_none());
    }

    #[test]
    fn run_payload_is_pod_round_trip() {
        let mut name = [0u16; 128];
        for (i, c) in "\\\\.\\pipe\\memo-abc".encode_utf16().enumerate() {
            name[i] = c;
        }
        let p = RunPayload {
            pipe_name: name,
            run_id: 0xDEADBEEF,
        };
        let bytes = p.as_bytes();
        assert_eq!(bytes.len(), core::mem::size_of::<RunPayload>());
        let p2 = RunPayload::from_bytes(bytes).unwrap();
        assert_eq!(p2.run_id, p.run_id);
        assert_eq!(p2.pipe_name, p.pipe_name);
    }
}
