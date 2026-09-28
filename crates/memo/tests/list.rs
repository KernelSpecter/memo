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
    assert!(
        r3.executed,
        "new file in listed dir must miss; stderr: {}",
        r3.stderr
    );
}

#[test]
fn single_name_lookup_is_not_a_full_listing() {
    // FindFirstFile("dir\\exact") issues a single-name NtQueryDirectoryFile
    // filter. That is a probe of one path, not an enumeration of the directory,
    // so an unrelated sibling appearing must not cause a miss.
    let sb = Sandbox::new("findfirst_probe");
    sb.write("d/a.txt", b"a");
    let target = abs(&sb.path("d/a.txt"));
    let op = format!("findfirst={}", target);

    let r1 = sb.run(&[&op]);
    assert!(r1.cached(), "stderr: {}", r1.stderr);

    sb.write("d/b.txt", b"b");
    let r2 = sb.run(&[&op]);
    assert!(
        r2.replayed(),
        "a single-name lookup must not fingerprint the whole dir; stderr: {}",
        r2.stderr
    );
}

#[test]
fn listed_dir_write_converges_then_replays() {
    // A command that lists a dir AND writes an output into it converges in two
    // real runs, then replays (spec §6.2 + §12). It must NOT replay run 1's
    // listing on run 2 — by then the dir really contains the output, which a real
    // run would see. The recorded listing is what the command saw (pre-write).
    let sb = Sandbox::new("list_write_converge");
    sb.write("d/a.txt", b"a");
    let d = abs(&sb.path("d"));
    let out = abs(&sb.path("d/out.txt"));

    let ops = [format!("list={}", d), format!("write={}|generated", out)];
    let ops_ref: Vec<&str> = ops.iter().map(|s| s.as_str()).collect();

    // Run 1: dir has {a.txt}; lists it, writes out.txt.
    let r1 = sb.run(&ops_ref);
    assert!(r1.executed && r1.cached(), "stderr: {}", r1.stderr);
    let run1_stdout = r1.stdout.clone();

    // Run 2: dir now has {a.txt, out.txt} (out.txt left by run 1). A real run
    // would list both, so this must re-execute, not replay run 1.
    let r2 = sb.run(&ops_ref);
    assert!(
        r2.executed,
        "run 2 must re-execute (dir changed); stderr: {}",
        r2.stderr
    );
    assert_ne!(
        r2.stdout, run1_stdout,
        "run 2's listing should differ from run 1's (out.txt now present)"
    );

    // Run 3: dir is steady {a.txt, out.txt}, matches run 2 → replay.
    let r3 = sb.run(&ops_ref);
    assert!(
        r3.replayed(),
        "run 3 should converge to a replay; stderr: {}",
        r3.stderr
    );
    assert_eq!(r3.stdout, r2.stdout, "replay reproduces run 2's output");
}
