//! Directory listing participates in the cache; new files in a listed dir miss.

mod it_util;
use it_util::{abs, Sandbox};

#[test]
fn listing_then_new_file_misses() {
    let sb = Sandbox::new("list_new");
    sb.write("d/a.txt", b"a");
    let d = abs(&sb.path("d"));

    let r1 = sb.run(&[&format!("list={}", d)]);
    assert!(r1.executed);
    assert!(r1.cached(), "stderr: {}", r1.stderr);
    assert!(r1.stdout.contains("a.txt"));

    // Unchanged → replay.
    let r2 = sb.run(&[&format!("list={}", d)]);
    assert!(r2.replayed(), "stderr: {}", r2.stderr);

    // A new external file appears in the listed dir → miss.
    sb.write("d/b.txt", b"b");
    let r3 = sb.run(&[&format!("list={}", d)]);
    assert!(r3.executed, "new file in listed dir must miss; stderr: {}", r3.stderr);
}

#[test]
fn listed_dir_churn_from_own_output_still_hits() {
    // A command that lists a dir AND writes an output into it should converge to
    // a steady replay: its own output must not disturb the listing fingerprint.
    let sb = Sandbox::new("list_churn");
    sb.write("d/a.txt", b"a");
    let d = abs(&sb.path("d"));
    let out = abs(&sb.path("d/out.txt"));

    let ops = [format!("list={}", d), format!("write={}|generated", out)];
    let ops_ref: Vec<&str> = ops.iter().map(|s| s.as_str()).collect();

    let r1 = sb.run(&ops_ref);
    assert!(r1.executed, "stderr: {}", r1.stderr);
    // Run 2 sees out.txt (from run 1) in the dir. It's the command's own output,
    // excluded from the listing fingerprint, so this should replay.
    let r2 = sb.run(&ops_ref);
    assert!(
        r2.replayed() || r2.cached(),
        "run 2 should replay or re-store, not error; stderr: {}",
        r2.stderr
    );
    // Run 3 should be a stable replay.
    let r3 = sb.run(&ops_ref);
    assert!(!r3.executed, "should converge to replay; stderr: {}", r3.stderr);
}
