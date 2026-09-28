//! %SystemRoot%: reads are ignored (OS files are out of scope), but a write
//! there changes machine state memo can't restore, so it must taint. The
//! tests point SystemRoot at a sandbox dir; memo reads it from its env.

mod it_util;
use it_util::{abs, Sandbox};

#[test]
fn write_under_system_root_is_not_cached() {
    let sb = Sandbox::new("sysroot_write");
    std::fs::create_dir_all(sb.path("fakewin")).unwrap();
    let sysroot = abs(&sb.path("fakewin"));
    let op = format!("write={}\\x.txt|data", sysroot);
    let r = sb.run_with_env(&["-v"], &[("SystemRoot", &sysroot)], &[&op]);
    assert_eq!(r.exit, 0, "stderr: {}", r.stderr);
    assert!(
        r.not_cached(),
        "write under SystemRoot must taint; stderr: {}",
        r.stderr
    );
    assert!(
        r.stderr.contains("SystemRoot"),
        "reason should name it; stderr: {}",
        r.stderr
    );
}

#[test]
fn read_and_failed_write_under_system_root_stay_cacheable() {
    let sb = Sandbox::new("sysroot_read");
    std::fs::create_dir_all(sb.path("fakewin")).unwrap();
    sb.write("fakewin/os.dll", b"os");
    let sysroot = abs(&sb.path("fakewin"));
    // A write the OS denies (here: the parent dir doesn't exist) changes
    // nothing, like a non-admin write attempt under the real C:\Windows.
    let ops = [
        format!("read={}\\os.dll", sysroot),
        format!("trywrite={}\\missing\\x.txt|data", sysroot),
    ];
    let ops_ref: Vec<&str> = ops.iter().map(|s| s.as_str()).collect();
    let env = [("SystemRoot", sysroot.as_str())];

    let r1 = sb.run_with_env(&[], &env, &ops_ref);
    assert!(
        r1.stdout.contains("TRYWROTE") && r1.stdout.contains("false"),
        "stdout: {}",
        r1.stdout
    );
    assert!(r1.cached(), "stderr: {}", r1.stderr);

    // Reads under SystemRoot are not inputs: changing the file still replays.
    sb.write("fakewin/os.dll", b"changed");
    let r2 = sb.run_with_env(&[], &env, &ops_ref);
    assert!(r2.replayed(), "stderr: {}", r2.stderr);
}
