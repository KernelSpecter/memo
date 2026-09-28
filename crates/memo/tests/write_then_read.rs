//! Write-then-read of a path that existed before the run (cargo rewriting a
//! `.d` dep-info file and reading it back). The read comes after the tree's own
//! write, so the pre-run content must have been captured at the first write.

mod it_util;
use it_util::{abs, Sandbox};

#[test]
fn overwrite_then_read_existing_file_is_cached_and_converges() {
    let sb = Sandbox::new("wtr_overwrite");
    sb.write("dep.d", b"old");
    let dep = abs(&sb.path("dep.d"));
    let ops = [format!("write={}|fresh", dep), format!("read={}", dep)];
    let ops_ref: Vec<&str> = ops.iter().map(|s| s.as_str()).collect();

    let r1 = sb.run(&ops_ref);
    assert!(r1.executed, "stderr: {}", r1.stderr);
    assert!(
        r1.cached(),
        "run 1 must be cacheable; stderr: {}",
        r1.stderr
    );

    // dep.d now holds the run's own output; pre-run state differs from run 1's.
    let r2 = sb.run(&ops_ref);
    assert!(r2.executed, "stderr: {}", r2.stderr);
    assert!(r2.cached(), "stderr: {}", r2.stderr);

    let r3 = sb.run(&ops_ref);
    assert!(
        r3.replayed(),
        "run 3 must converge to a replay; stderr: {}",
        r3.stderr
    );
    assert!(!r3.executed);
}

/// A run that rewrites an unread output with the bytes it already had must
/// still record it: nothing pins the output's state at replay time.
#[test]
fn identical_rewrite_of_unread_output_is_still_restored() {
    let sb = Sandbox::new("wtr_identical_rewrite");
    sb.write("a.txt", b"hello");
    let a = abs(&sb.path("a.txt"));
    let out = abs(&sb.path("out.bin"));
    let op = format!("concat={}||{}", a, out);

    let r1 = sb.run(&[&op]);
    assert!(r1.cached(), "stderr: {}", r1.stderr);
    // Real run again (pre-run out.bin == final out.bin == "hello"), stored newest.
    let r2 = sb.run_with_flags(&["--no-read"], &[&op]);
    assert!(r2.executed && r2.cached(), "stderr: {}", r2.stderr);

    sb.write("out.bin", b"junk");
    let r3 = sb.run(&[&op]);
    assert!(r3.replayed(), "stderr: {}", r3.stderr);
    assert_eq!(
        std::fs::read(sb.path("out.bin")).unwrap(),
        b"hello",
        "replay left a stale output"
    );
}

#[test]
fn append_only_pins_pre_run_content() {
    // A pure append (no read op) whose output is the file itself: the appended
    // result depends on the pre-run prefix, so the pre-run content must be
    // pinned even though nothing "read" the file with a read handle.
    let sb = Sandbox::new("append_only_pin");
    let log = abs(&sb.path("log.txt"));
    let op = format!("append={}|B", log);

    sb.write("log.txt", b"AAAA");
    let r1 = sb.run(&[&op]);
    assert!(r1.cached(), "stderr: {}", r1.stderr);
    assert_eq!(std::fs::read(sb.path("log.txt")).unwrap(), b"AAAAB");

    // Same pre-run content -> replay restores the same appended result.
    sb.write("log.txt", b"AAAA");
    let r2 = sb.run(&[&op]);
    assert!(r2.replayed(), "stderr: {}", r2.stderr);
    assert_eq!(std::fs::read(sb.path("log.txt")).unwrap(), b"AAAAB");

    // Same size, different content: replaying AAAAB would be stale.
    sb.write("log.txt", b"ZZZZ");
    let r3 = sb.run(&[&op]);
    assert!(
        r3.executed,
        "append must not replay after pre-run content changed; stderr: {}",
        r3.stderr
    );
    assert_eq!(std::fs::read(sb.path("log.txt")).unwrap(), b"ZZZZB");
}

#[test]
fn append_then_read_misses_when_pre_run_content_changes() {
    let sb = Sandbox::new("wtr_append");
    let log = abs(&sb.path("log.txt"));
    let copy = abs(&sb.path("copy.txt"));
    // copy.txt = pre-run log.txt ++ "B": depends on the pre-run *content*.
    let ops = [
        format!("append={}|B", log),
        format!("concat={}||{}", log, copy),
    ];
    let ops_ref: Vec<&str> = ops.iter().map(|s| s.as_str()).collect();

    sb.write("log.txt", b"AAAA");
    let r1 = sb.run(&ops_ref);
    assert!(r1.executed, "stderr: {}", r1.stderr);
    assert!(
        r1.cached(),
        "run 1 must be cacheable; stderr: {}",
        r1.stderr
    );
    assert_eq!(std::fs::read(sb.path("copy.txt")).unwrap(), b"AAAAB");

    // Same pre-run content as run 1 → replay restores run 1's outputs.
    sb.write("log.txt", b"AAAA");
    let r2 = sb.run(&ops_ref);
    assert!(r2.replayed(), "stderr: {}", r2.stderr);
    assert_eq!(std::fs::read(sb.path("copy.txt")).unwrap(), b"AAAAB");

    // Same size, different content → a real run gives ZZZZB; replaying AAAAB
    // would be stale.
    sb.write("log.txt", b"ZZZZ");
    let r3 = sb.run(&ops_ref);
    assert!(
        r3.executed,
        "must not replay after pre-run content changed; stderr: {}",
        r3.stderr
    );
    assert_eq!(std::fs::read(sb.path("copy.txt")).unwrap(), b"ZZZZB");
}
