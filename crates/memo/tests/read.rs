//! First end-to-end test: reading a file is traced, stored, and replayed.

mod it_util;
use it_util::{abs, Sandbox};

#[test]
fn read_is_cached_and_replayed() {
    let sb = Sandbox::new("read_basic");
    sb.write("a.txt", b"hello world");
    let a = abs(&sb.path("a.txt"));

    // Run 1: miss → executes for real, stores.
    let r1 = sb.run(&[&format!("read={}", a)]);
    assert_eq!(r1.exit, 0, "stderr: {}", r1.stderr);
    assert!(r1.executed, "run 1 must execute for real");
    assert!(
        r1.stdout.contains(&format!("READ {} 11", a)),
        "stdout: {:?}",
        r1.stdout
    );
    assert!(
        r1.cached(),
        "run 1 should store an entry; stderr: {}",
        r1.stderr
    );

    // Run 2: hit → replays without executing, identical stdout.
    let r2 = sb.run(&[&format!("read={}", a)]);
    assert_eq!(r2.exit, 0);
    assert!(
        !r2.executed,
        "run 2 must NOT execute (replay); stderr: {}",
        r2.stderr
    );
    assert!(r2.replayed(), "run 2 should replay; stderr: {}", r2.stderr);
    assert_eq!(
        r1.stdout, r2.stdout,
        "replayed stdout must match real stdout"
    );
}

#[test]
fn changed_input_causes_miss() {
    let sb = Sandbox::new("read_change");
    sb.write("a.txt", b"one");
    let a = abs(&sb.path("a.txt"));

    let r1 = sb.run(&[&format!("read={}", a)]);
    assert!(r1.executed);
    assert!(r1.cached(), "stderr: {}", r1.stderr);

    // Change the file → next run must miss and execute again.
    std::thread::sleep(std::time::Duration::from_millis(20));
    sb.write("a.txt", b"two-different");

    let r2 = sb.run(&[&format!("read={}", a)]);
    assert!(
        r2.executed,
        "changed input must force real execution; stderr: {}",
        r2.stderr
    );
    assert!(
        r2.stdout.contains(&format!("READ {} 13", a)),
        "stdout: {:?}",
        r2.stdout
    );
}
