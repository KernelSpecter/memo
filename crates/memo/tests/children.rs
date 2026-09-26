//! Child (and grandchild) processes are injected and their file access tracked.

mod it_util;
use it_util::{abs, Sandbox};

#[test]
fn child_reads_are_tracked() {
    let sb = Sandbox::new("child_read");
    sb.write("b.txt", b"child-data");
    let b = abs(&sb.path("b.txt"));

    // Parent spawns a child probe that reads b.txt.
    let op = format!("spawn=read={}", b);

    let r1 = sb.run(&[&op]);
    assert_eq!(r1.exit, 0, "stderr: {}", r1.stderr);
    // Two processes executed: parent + child.
    assert!(r1.executions >= 2, "expected parent+child to run, got {}", r1.executions);
    assert!(r1.cached(), "stderr: {}", r1.stderr);
    assert!(r1.stdout.contains(&format!("READ {} 10", b)));

    // Unchanged → replay, nothing executes.
    let r2 = sb.run(&[&op]);
    assert!(r2.replayed(), "stderr: {}", r2.stderr);
    assert_eq!(r2.executions, 0, "replay must not execute any process");

    // Change the file the CHILD read → the whole run must miss.
    std::thread::sleep(std::time::Duration::from_millis(20));
    sb.write("b.txt", b"child-data-modified");
    let r3 = sb.run(&[&op]);
    assert!(
        r3.executed,
        "changing a file read by a child must miss; stderr: {}",
        r3.stderr
    );
}

#[test]
fn grandchild_reads_are_tracked() {
    let sb = Sandbox::new("grandchild_read");
    sb.write("c.txt", b"deep");
    let c = abs(&sb.path("c.txt"));

    // parent -> child -> grandchild, which reads c.txt.
    let op = format!("spawn=spawn=read={}", c);

    let r1 = sb.run(&[&op]);
    assert_eq!(r1.exit, 0, "stderr: {}", r1.stderr);
    assert!(r1.executions >= 3, "parent+child+grandchild, got {}", r1.executions);
    assert!(r1.cached(), "stderr: {}", r1.stderr);

    let r2 = sb.run(&[&op]);
    assert!(r2.replayed(), "stderr: {}", r2.stderr);

    std::thread::sleep(std::time::Duration::from_millis(20));
    sb.write("c.txt", b"deep-changed");
    let r3 = sb.run(&[&op]);
    assert!(r3.executed, "changing a file read by a grandchild must miss; stderr: {}", r3.stderr);
}
