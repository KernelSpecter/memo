//! Outputs are captured and restored on replay.

mod it_util;
use it_util::{abs, Sandbox};

#[test]
fn output_is_restored_on_replay() {
    let sb = Sandbox::new("write_restore");
    let out = abs(&sb.path("out.txt"));
    let op = format!("write={}|generated-content", out);

    let r1 = sb.run(&[&op]);
    assert!(r1.executed);
    assert!(r1.cached(), "stderr: {}", r1.stderr);
    assert_eq!(
        std::fs::read(sb.path("out.txt")).unwrap(),
        b"generated-content"
    );

    // Delete the output; replay must recreate it byte-for-byte without running.
    std::fs::remove_file(sb.path("out.txt")).unwrap();
    let r2 = sb.run(&[&op]);
    assert!(r2.replayed(), "stderr: {}", r2.stderr);
    assert!(!r2.executed, "replay must not execute");
    assert_eq!(
        std::fs::read(sb.path("out.txt")).unwrap(),
        b"generated-content",
        "output must be restored on replay"
    );
}

#[test]
fn rename_output_restored() {
    let sb = Sandbox::new("rename_out");
    sb.write("src.txt", b"payload");
    let src = abs(&sb.path("src.txt"));
    let dst = abs(&sb.path("dst.txt"));
    let op = format!("rename={}|{}", src, dst);

    let r1 = sb.run(&[&op]);
    assert!(r1.executed, "stderr: {}", r1.stderr);
    assert!(r1.cached(), "stderr: {}", r1.stderr);
    assert!(sb.path("dst.txt").exists());
    assert!(!sb.path("src.txt").exists());

    // Reset to the pre-run state and replay.
    sb.write("src.txt", b"payload");
    let _ = std::fs::remove_file(sb.path("dst.txt"));
    let r2 = sb.run(&[&op]);
    assert!(
        r2.replayed(),
        "restored pre-run state should replay; stderr: {}",
        r2.stderr
    );
    assert!(sb.path("dst.txt").exists(), "renamed target restored");
    assert!(!sb.path("src.txt").exists(), "source removed on replay");
}

#[test]
fn rename_with_missing_source_does_not_replay() {
    // The rename source's pre-run existence is pinned: if it's gone, a real run
    // would rename nothing, so replaying (and recreating dst from cache) is stale.
    let sb = Sandbox::new("rename_missing_src");
    sb.write("src.txt", b"payload");
    let src = abs(&sb.path("src.txt"));
    let dst = abs(&sb.path("dst.txt"));
    let op = format!("rename={}|{}", src, dst);

    let r1 = sb.run(&[&op]);
    assert!(r1.cached(), "stderr: {}", r1.stderr);

    // Both gone: the source no longer exists.
    let _ = std::fs::remove_file(sb.path("src.txt"));
    let _ = std::fs::remove_file(sb.path("dst.txt"));
    let r2 = sb.run(&[&op]);
    assert!(
        r2.executed,
        "rename with a missing source must miss, not replay a stale dst; stderr: {}",
        r2.stderr
    );
    assert!(!sb.path("dst.txt").exists(), "no stale dst created");
}

#[test]
fn delete_output_restored() {
    let sb = Sandbox::new("delete_out");
    sb.write("victim.txt", b"bye");
    let victim = abs(&sb.path("victim.txt"));
    let op = format!("delete={}", victim);

    let r1 = sb.run(&[&op]);
    assert!(r1.executed, "stderr: {}", r1.stderr);
    assert!(r1.cached(), "stderr: {}", r1.stderr);
    assert!(!sb.path("victim.txt").exists());

    // Recreate the victim with identical content; replay must delete it again.
    sb.write("victim.txt", b"bye");
    let r2 = sb.run(&[&op]);
    assert!(
        r2.replayed(),
        "restored pre-run state should replay; stderr: {}",
        r2.stderr
    );
    assert!(
        !sb.path("victim.txt").exists(),
        "replay must re-delete the file"
    );
}
