//! C1: the three file hooks the spec §4.2 lists that were never installed —
//! NtQueryInformationByName (path stat used by Python 3.12+/.NET/Rust std),
//! the pre-Win8 NtQueryDirectoryFile (libuv/Node readdir, .NET), and
//! NtDeleteFile (delete by name). memo-probe drives each directly via FFI
//! (Rust std doesn't route through them on this toolchain), so a run that only
//! touches a path through one of these must still observe it — otherwise a
//! change to that path would replay stale.

mod it_util;
use it_util::{abs, Sandbox};

#[test]
fn query_information_by_name_probe_is_observed() {
    let sb = Sandbox::new("qbyname_absent");
    let target = abs(&sb.path("flag.txt")); // absent at first
    let op = format!("qbyname={}", target);

    let r1 = sb.run(&[&op]);
    assert!(r1.cached(), "run 1 must cache; stderr: {}", r1.stderr);

    // Create the file the probe checked for via NtQueryInformationByName.
    sb.write("flag.txt", b"x");
    let r2 = sb.run(&[&op]);
    assert!(
        r2.executed,
        "creating a path probed via NtQueryInformationByName must miss, not replay; stderr: {}",
        r2.stderr
    );
}

#[test]
fn query_directory_file_nonex_is_observed() {
    let sb = Sandbox::new("qdirfile_churn");
    std::fs::create_dir_all(sb.path("d")).unwrap();
    sb.write("d/a.txt", b"a");
    let dir = abs(&sb.path("d"));
    let op = format!("qdirfile={}", dir);

    let r1 = sb.run(&[&op]);
    assert!(r1.cached(), "run 1 must cache; stderr: {}", r1.stderr);

    // An external file appears in the directory the probe enumerated.
    sb.write("d/b.txt", b"b");
    let r2 = sb.run(&[&op]);
    assert!(
        r2.executed,
        "a new file in a dir listed via NtQueryDirectoryFile must miss; stderr: {}",
        r2.stderr
    );
}

#[test]
fn nt_delete_file_is_recorded() {
    let sb = Sandbox::new("ntdelete");
    sb.write("victim.txt", b"bye"); // 3 bytes
    let victim = abs(&sb.path("victim.txt"));
    let op = format!("ntdelete={}", victim);

    let r1 = sb.run(&[&op]);
    assert!(r1.cached(), "run 1 must cache; stderr: {}", r1.stderr);
    assert!(
        !sb.path("victim.txt").exists(),
        "probe should have deleted victim.txt"
    );

    // Recreate with identical size/content so the recorded pre-run input still
    // matches; the recorded deletion (an output) must then replay and delete it.
    sb.write("victim.txt", b"bye");
    let r2 = sb.run(&[&op]);
    assert!(r2.replayed(), "run 2 should replay; stderr: {}", r2.stderr);
    assert!(
        !sb.path("victim.txt").exists(),
        "replay must reproduce the NtDeleteFile deletion; stderr: {}",
        r2.stderr
    );
}
