//! I3: when a replay can't be completed — a corrupt/missing cached blob — memo
//! falls back to running the command for real instead of failing or restoring
//! corrupt bytes (spec §10).

mod it_util;
use it_util::{abs, Sandbox};

/// Overwrite every content-addressed blob under the cache with garbage.
fn corrupt_all_blobs(cache: &std::path::Path) {
    let cas = cache.join("cas");
    if !cas.exists() {
        return;
    }
    for shard in std::fs::read_dir(&cas).into_iter().flatten().flatten() {
        if shard.path().is_dir() {
            for f in std::fs::read_dir(shard.path())
                .into_iter()
                .flatten()
                .flatten()
            {
                let _ = std::fs::write(f.path(), b"CORRUPT");
            }
        }
    }
}

#[test]
fn corrupt_blob_falls_back_to_a_real_run() {
    let sb = Sandbox::new("replay_fallback");
    let out = abs(&sb.path("out.txt"));
    let op = format!("write={}|generated-content", out);

    let r1 = sb.run(&[&op]);
    assert!(r1.cached(), "run 1 must cache; stderr: {}", r1.stderr);

    // Corrupt the cached blobs (output content + console). The inputs still
    // verify, so memo will attempt a replay and must detect the bad blob.
    std::fs::remove_file(sb.path("out.txt")).unwrap();
    corrupt_all_blobs(&sb.cache);

    let r2 = sb.run(&[&op]);
    assert_eq!(r2.exit, 0, "must not fail; stderr: {}", r2.stderr);
    assert!(
        r2.executed,
        "a corrupt blob must fall back to a real run, not exit 125; stderr: {}",
        r2.stderr
    );
    assert_eq!(
        std::fs::read(sb.path("out.txt")).unwrap(),
        b"generated-content",
        "the real run produces the correct output"
    );
}
