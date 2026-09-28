//! C4: a child process's own executable is a read input. Replacing the child
//! exe between runs (same command line) must miss, not replay the old result.

mod it_util;
use it_util::{abs, probe_exe, Sandbox};

#[test]
fn child_exe_replaced_between_runs_misses() {
    let sb = Sandbox::new("child_exe");
    let probe = probe_exe();
    let tool = sb.path("tool.exe");
    // tool.exe is a copy of memo-probe, so it runs the op we pass and is injected.
    std::fs::copy(&probe, &tool).unwrap();
    let op = format!("runexe={}|exit=0", abs(&tool));

    let r1 = sb.run(&[&op]);
    assert!(r1.cached(), "run 1 must cache; stderr: {}", r1.stderr);

    // Replace tool.exe with a byte-different but still-runnable copy (trailing
    // data after a PE's sections is ignored by the loader). Same behavior,
    // different content — the recorded child-image read must no longer match.
    let mut bytes = std::fs::read(&probe).unwrap();
    bytes.extend_from_slice(b"MEMO-PADDING-BYTES-TO-CHANGE-CONTENT");
    std::fs::write(&tool, &bytes).unwrap();

    let r2 = sb.run(&[&op]);
    assert!(
        r2.executed,
        "replacing the child executable must miss, not replay; stderr: {}",
        r2.stderr
    );
}
