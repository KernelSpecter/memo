//! C2a: a mutation is recorded only when the operation succeeds. A failed create
//! or write must not become a spurious input or output, and the run must stay
//! cacheable.

mod it_util;
use it_util::{abs, Sandbox};

#[test]
fn failed_create_on_existing_dir_stays_cacheable_and_replays() {
    let sb = Sandbox::new("mkdir_exists");
    std::fs::create_dir_all(sb.path("d")).unwrap();
    let d = abs(&sb.path("d"));
    // mkdirstrict on an existing dir issues a FILE_CREATE that fails.
    let op = format!("mkdirstrict={}", d);

    let r1 = sb.run(&[&op]);
    assert!(
        r1.cached(),
        "a failed create must not taint; stderr: {}",
        r1.stderr
    );
    assert!(
        r1.stdout.contains("false"),
        "the create should have failed; stdout: {}",
        r1.stdout
    );

    let r2 = sb.run(&[&op]);
    assert!(
        r2.replayed(),
        "nothing changed, should replay; stderr: {}",
        r2.stderr
    );
}
