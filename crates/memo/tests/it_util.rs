//! Shared helpers for memo integration tests. Each test gets an isolated
//! sandbox working directory and its own MEMO_DIR, and runs the real memo.exe
//! (which injects the real memo_hook.dll) against the memo-probe fixture.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Once;

static BUILD: Once = Once::new();

/// target/debug directory (where cargo puts the built binaries).
pub fn target_dir() -> PathBuf {
    // CARGO_MANIFEST_DIR = crates/memo
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.join("..").join("..").join("target").join("debug")
}

/// Ensure memo.exe, memo_hook.dll and memo-probe.exe are all built.
pub fn ensure_built() {
    BUILD.call_once(|| {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let workspace = manifest.join("..").join("..");
        let status = Command::new(env!("CARGO"))
            .current_dir(&workspace)
            .args(["build", "-p", "memo", "-p", "memo-hook", "-p", "memo-probe"])
            .status()
            .expect("cargo build for integration prerequisites");
        assert!(status.success(), "failed to build integration prerequisites");
    });
}

pub fn memo_exe() -> PathBuf {
    target_dir().join("memo.exe")
}

pub fn hook_dll() -> PathBuf {
    target_dir().join("memo_hook.dll")
}

pub fn probe_exe() -> PathBuf {
    target_dir().join("memo-probe.exe")
}

pub struct Sandbox {
    pub work: PathBuf,
    pub cache: PathBuf,
    pub marker: PathBuf,
}

impl Sandbox {
    pub fn new(name: &str) -> Sandbox {
        ensure_built();
        let base = target_dir().join("..").join("memo-it").join(name);
        let _ = std::fs::remove_dir_all(&base);
        let work = base.join("work");
        let cache = base.join("cache");
        std::fs::create_dir_all(&work).unwrap();
        std::fs::create_dir_all(&cache).unwrap();
        // Marker lives in the OS temp dir, which memo ignores, so probe
        // executions are counted without being tracked as inputs/outputs.
        let marker = std::env::temp_dir().join(format!("memo-marker-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_file(&marker);
        Sandbox { work, cache, marker }
    }

    pub fn path(&self, rel: &str) -> PathBuf {
        self.work.join(rel)
    }

    pub fn write(&self, rel: &str, content: &[u8]) {
        let p = self.path(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(p, content).unwrap();
    }

    /// Number of times the probe actually executed across all runs so far.
    pub fn marker_count(&self) -> u64 {
        std::fs::metadata(&self.marker).map(|m| m.len()).unwrap_or(0)
    }

    /// Run memo with the given probe ops. Returns the run outcome.
    pub fn run(&self, ops: &[&str]) -> RunOutcome {
        self.run_with_flags(&[], ops)
    }

    pub fn run_with_flags(&self, memo_flags: &[&str], ops: &[&str]) -> RunOutcome {
        let mut cmd = Command::new(memo_exe());
        cmd.current_dir(&self.work);
        cmd.env("MEMO_DIR", &self.cache);
        cmd.env("MEMO_PROBE_MARKER", &self.marker);
        cmd.env("MEMO_FORCE_STATUS", "1");
        for f in memo_flags {
            cmd.arg(f);
        }
        cmd.arg(probe_exe());
        for op in ops {
            cmd.arg(op);
        }
        let before = self.marker_count();
        let out = cmd.output().expect("run memo");
        let after = self.marker_count();
        RunOutcome {
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            exit: out.status.code().unwrap_or(-1),
            executed: after > before,
            executions: after - before,
        }
    }
}

pub struct RunOutcome {
    pub stdout: String,
    pub stderr: String,
    pub exit: i32,
    /// Whether the probe executed for real this run (marker grew).
    pub executed: bool,
    /// How many probe processes executed this run.
    pub executions: u64,
}

impl RunOutcome {
    pub fn cached(&self) -> bool {
        self.stderr.contains("cached")
    }
    pub fn replayed(&self) -> bool {
        self.stderr.contains("replayed")
    }
    pub fn not_cached(&self) -> bool {
        self.stderr.contains("not cached")
    }
}

/// Absolute path string (as the probe/memo see it) for an op argument.
pub fn abs(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}
