//! Existence probes (positive and negative) participate in the cache key.

mod it_util;
use it_util::{abs, Sandbox};

#[test]
fn positive_probe_then_delete_misses() {
    let sb = Sandbox::new("probe_pos");
    sb.write("f.txt", b"x");
    let f = abs(&sb.path("f.txt"));

    let r1 = sb.run(&[&format!("probe={}", f)]);
    assert!(r1.executed);
    assert!(r1.cached(), "stderr: {}", r1.stderr);
    assert!(r1.stdout.contains("true"));

    // Same state → replay.
    let r2 = sb.run(&[&format!("probe={}", f)]);
    assert!(r2.replayed(), "stderr: {}", r2.stderr);
    assert!(!r2.executed);

    // Delete the probed file → existence changed → miss.
    std::fs::remove_file(sb.path("f.txt")).unwrap();
    let r3 = sb.run(&[&format!("probe={}", f)]);
    assert!(
        r3.executed,
        "deleting a probed file must miss; stderr: {}",
        r3.stderr
    );
    assert!(r3.stdout.contains("false"));
}

#[test]
fn negative_probe_then_create_misses() {
    let sb = Sandbox::new("probe_neg");
    let f = abs(&sb.path("ghost.txt"));

    let r1 = sb.run(&[&format!("probe={}", f)]);
    assert!(r1.executed);
    assert!(r1.cached(), "stderr: {}", r1.stderr);
    assert!(r1.stdout.contains("false"));

    let r2 = sb.run(&[&format!("probe={}", f)]);
    assert!(r2.replayed(), "stderr: {}", r2.stderr);

    // Create the previously-absent file → miss.
    sb.write("ghost.txt", b"now here");
    let r3 = sb.run(&[&format!("probe={}", f)]);
    assert!(
        r3.executed,
        "creating a probed-absent file must miss; stderr: {}",
        r3.stderr
    );
    assert!(r3.stdout.contains("true"));
}
