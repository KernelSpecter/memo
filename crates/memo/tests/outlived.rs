//! I1 / spec §5.4: a process that outlives the command taints the run (not
//! cached) but is NOT killed — build daemons and `start /b` children keep
//! running as they would without memo.

mod it_util;
use it_util::Sandbox;
use std::time::{Duration, Instant};

#[test]
fn outliving_process_is_tainted_but_not_killed() {
    let sb = Sandbox::new("outlived");
    // Marker under %TEMP% (ignored by memo). The detached child writes it after
    // sleeping past memo's post-exit grace period.
    let marker = std::env::temp_dir().join(format!("memo-outlived-{}", std::process::id()));
    let _ = std::fs::remove_file(&marker);

    let op = format!("detach=4000|{}", marker.display());
    let r = sb.run(&[&op]);
    assert!(
        r.not_cached(),
        "a run with an outliving process must not be cached; stderr: {}",
        r.stderr
    );

    // The child was NOT killed: it finishes its sleep and writes the marker.
    let deadline = Instant::now() + Duration::from_secs(15);
    while !marker.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    let survived = marker.exists();
    let _ = std::fs::remove_file(&marker);
    assert!(
        survived,
        "the outliving child must keep running (memo must not kill the tree)"
    );
}
