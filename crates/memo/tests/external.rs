//! C3: a file/dir the tree observed that is changed by someone else DURING the
//! run must taint — memo must not record a state the command didn't observe.
//! Each test runs memo on a probe that observes a path, signals ready, then
//! sleeps; a background thread makes the external change in that window.

mod it_util;
use it_util::{abs, Sandbox};
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Spawn a thread that waits for `ready` to appear (the probe signals it after
/// the observation), then runs `change`. Returns the join handle.
fn mid_run<F: FnOnce() + Send + 'static>(ready: PathBuf, change: F) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(15);
        while !ready.exists() {
            if Instant::now() > deadline {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        // The probe signals ready right after the observation; give the read/list
        // a beat to be fully recorded before we change things.
        std::thread::sleep(Duration::from_millis(50));
        change();
    })
}

fn ready_path(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("memo-ext-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

#[test]
fn read_file_deleted_mid_run_is_not_cached() {
    let sb = Sandbox::new("ext_read_del");
    sb.write("f.txt", b"data");
    let f = abs(&sb.path("f.txt"));
    let ready = ready_path("readdel");
    let victim = sb.path("f.txt");

    let m = mid_run(ready.clone(), move || {
        let _ = std::fs::remove_file(&victim);
    });
    let ops = [
        format!("read={}", f),
        format!("ready={}", ready.display()),
        "sleep=1500".to_string(),
    ];
    let ops_ref: Vec<&str> = ops.iter().map(|s| s.as_str()).collect();
    let r = sb.run(&ops_ref);
    let _ = m.join();
    assert!(
        r.not_cached(),
        "a read file deleted mid-run must taint; stderr: {}",
        r.stderr
    );
}

#[test]
fn external_file_in_listed_dir_mid_run_is_not_cached() {
    let sb = Sandbox::new("ext_list_add");
    sb.write("d/a.txt", b"a");
    let d = abs(&sb.path("d"));
    let ready = ready_path("listadd");
    let intruder = sb.path("d/b.txt");

    let m = mid_run(ready.clone(), move || {
        let _ = std::fs::write(&intruder, b"b");
    });
    let ops = [
        format!("list={}", d),
        format!("ready={}", ready.display()),
        "sleep=1500".to_string(),
    ];
    let ops_ref: Vec<&str> = ops.iter().map(|s| s.as_str()).collect();
    let r = sb.run(&ops_ref);
    let _ = m.join();
    assert!(
        r.not_cached(),
        "an external file appearing in a listed dir mid-run must taint; stderr: {}",
        r.stderr
    );
}

#[test]
fn probed_absent_path_created_mid_run_is_not_cached() {
    let sb = Sandbox::new("ext_probe_create");
    let ghost = abs(&sb.path("ghost.txt")); // absent
    let ready = ready_path("probecreate");
    let created = sb.path("ghost.txt");

    let m = mid_run(ready.clone(), move || {
        let _ = std::fs::write(&created, b"surprise");
    });
    let ops = [
        format!("probe={}", ghost),
        format!("ready={}", ready.display()),
        "sleep=1500".to_string(),
    ];
    let ops_ref: Vec<&str> = ops.iter().map(|s| s.as_str()).collect();
    let r = sb.run(&ops_ref);
    let _ = m.join();
    assert!(
        r.not_cached(),
        "a path probed absent then created mid-run must taint; stderr: {}",
        r.stderr
    );
}
