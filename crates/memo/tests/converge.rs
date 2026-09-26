//! Read-then-write (a command that reads its own previous output) converges to a
//! steady replay within two real runs — the core of the mtime-drop rule.

mod it_util;
use it_util::{abs, Sandbox};

#[test]
fn read_then_write_converges() {
    let sb = Sandbox::new("converge_rtw");
    let cache = abs(&sb.path("state.cache"));
    // Each run reads the cache file then writes a fixed steady value.
    let ops = [
        format!("read={}", cache),
        format!("write={}|STEADY", cache),
    ];
    let ops_ref: Vec<&str> = ops.iter().map(|s| s.as_str()).collect();

    // Run 1: cache absent → reads 0 bytes, writes STEADY.
    let r1 = sb.run(&ops_ref);
    assert!(r1.executed, "stderr: {}", r1.stderr);
    assert_eq!(std::fs::read(sb.path("state.cache")).unwrap(), b"STEADY");

    // Run 2: cache now = STEADY (from run 1) → different read → miss, re-store.
    let r2 = sb.run(&ops_ref);
    assert!(r2.executed, "run 2 should still execute (input changed); stderr: {}", r2.stderr);

    // Run 3: cache still = STEADY, matches run 2's recorded input → replay.
    let r3 = sb.run(&ops_ref);
    assert!(
        !r3.executed,
        "run 3 must converge to a replay; stderr: {}",
        r3.stderr
    );
    assert!(r3.replayed(), "stderr: {}", r3.stderr);
}
