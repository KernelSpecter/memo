//! `memo explain` reports whether the command would replay and, if not, the
//! first input that changed. `memo stats` reports counters.

mod it_util;
use it_util::{abs, Sandbox};

#[test]
fn explain_reports_replay_then_first_mismatch() {
    let sb = Sandbox::new("explain_basic");
    sb.write("a.txt", b"hello");
    let a = abs(&sb.path("a.txt"));
    let op = format!("read={}", a);

    // Cache it.
    let r1 = sb.run(&[&op]);
    assert!(r1.cached(), "stderr: {}", r1.stderr);

    // explain: would replay.
    let e1 = sb.explain(&[&op]);
    assert!(
        e1.stdout.contains("would replay"),
        "stdout: {:?}",
        e1.stdout
    );

    // Change the input; explain should now report a miss naming the file.
    std::thread::sleep(std::time::Duration::from_millis(20));
    sb.write("a.txt", b"changed");
    let e2 = sb.explain(&[&op]);
    assert!(e2.stdout.contains("would miss"), "stdout: {:?}", e2.stdout);
    assert!(e2.stdout.contains("a.txt"), "should name the changed file: {:?}", e2.stdout);
}

#[test]
fn stats_reports_hits_and_stores() {
    let sb = Sandbox::new("stats_basic");
    sb.write("a.txt", b"x");
    let a = abs(&sb.path("a.txt"));
    let op = format!("read={}", a);

    sb.run(&[&op]); // store
    sb.run(&[&op]); // hit

    let s = sb.subcommand(&["stats"]);
    assert!(s.stdout.contains("entries:"), "stdout: {:?}", s.stdout);
    assert!(s.stdout.contains("hits:"), "stdout: {:?}", s.stdout);
    // At least one store and one hit recorded.
    assert!(
        s.stdout.lines().any(|l| l.starts_with("stores:") && !l.contains(" 0")),
        "expected a nonzero store count: {:?}",
        s.stdout
    );
}
