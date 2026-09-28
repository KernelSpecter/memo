//! Ctrl+C during a run (spec §10): memo stays alive, the command gets the event
//! itself, and the run is never cached, even when the command handles the
//! interrupt and exits 0 (a replay of its partial run would be stale).
//!
//! Two independent reports make the run uncacheable: memo's own console
//! handler, and the hook's handler inside the command, which runs before the
//! command's handlers and so can't lose a race with the command exiting.

mod it_util;
use it_util::{memo_exe, probe_exe, Sandbox};
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// A new console with no window: an event sent to it reaches memo and the
/// command, but not the test harness.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

struct Interrupted {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// Run memo on a probe that installs a swallowing handler, signals ready, then
/// works for a while; deliver `event` ("c" or "break") to memo's console
/// mid-run. `pre` ops run first.
fn interrupted_run(sb: &Sandbox, event: &str, pre: &[&str]) -> (Interrupted, Vec<String>) {
    // Under %TEMP%, which memo ignores, so it isn't an output.
    let ready = std::env::temp_dir().join(format!("memo-ready-{}-{}", event, std::process::id()));
    let _ = std::fs::remove_file(&ready);
    let mut ops: Vec<String> = pre.iter().map(|s| s.to_string()).collect();
    ops.extend([
        "ctrlc=swallow".to_string(),
        format!("ready={}", ready.display()),
        "sleep=2000".to_string(),
        "print=finished".to_string(),
    ]);

    // Same environment as Sandbox::run, so a later sb.run shares the cache key.
    let child = Command::new(memo_exe())
        .current_dir(&sb.work)
        .env("MEMO_DIR", &sb.cache)
        .env("MEMO_PROBE_MARKER", &sb.marker)
        .env("MEMO_FORCE_STATUS", "1")
        .arg("-v")
        .arg(probe_exe())
        .args(&ops)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .expect("spawn memo");

    let deadline = Instant::now() + Duration::from_secs(20);
    while !ready.exists() {
        assert!(Instant::now() < deadline, "the command never became ready");
        std::thread::sleep(Duration::from_millis(20));
    }
    let sent = Command::new(probe_exe())
        .arg(format!("sendctrl={}:{}", event, child.id()))
        .status()
        .expect("run sendctrl");
    assert!(
        sent.success(),
        "could not deliver the event to memo's console"
    );

    let out = child.wait_with_output().expect("wait for memo");
    let _ = std::fs::remove_file(&ready);
    let run = Interrupted {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    };
    // memo survived and passed the command's output and exit code through.
    assert_eq!(run.code, Some(0), "stderr: {}", run.stderr);
    assert!(
        run.stdout.contains("finished"),
        "stdout: {}\nstderr: {}",
        run.stdout,
        run.stderr
    );
    assert!(
        run.stderr
            .contains("not cached: the command was interrupted"),
        "stderr: {}",
        run.stderr
    );
    (run, ops)
}

/// Nothing was stored: the same command now runs for real.
fn assert_not_stored(sb: &Sandbox, ops: &[String]) {
    let ops_ref: Vec<&str> = ops.iter().map(|s| s.as_str()).collect();
    let r = sb.run(&ops_ref);
    assert!(r.executed, "stderr: {}", r.stderr);
    assert!(r.cached(), "stderr: {}", r.stderr);
}

/// Ctrl+Break reaches every process whatever its ignore-Ctrl+C flag, so this
/// exercises memo's own handler: it must keep memo alive and taint the run.
#[test]
fn ctrl_break_keeps_memo_alive_and_is_not_cached() {
    let sb = Sandbox::new("interrupt_break");
    let (run, ops) = interrupted_run(&sb, "break", &[]);
    assert!(
        run.stderr.contains("reached memo"),
        "memo's handler did not report; stderr: {}",
        run.stderr
    );
    assert_not_stored(&sb, &ops);
}

/// The hook's report from inside the command, on its own. The command clears
/// any inherited ignore-Ctrl+C flag so the event reaches it; memo may still
/// ignore it (it does when the tests run under a CREATE_NEW_PROCESS_GROUP
/// parent), so only the hook's report is asserted.
#[test]
fn ctrl_c_handled_by_the_command_is_reported_from_inside_it() {
    let sb = Sandbox::new("interrupt_c");
    let (run, ops) = interrupted_run(&sb, "c", &["ctrlc=enable"]);
    assert!(
        run.stderr.contains("in pid"),
        "the hook did not report; stderr: {}",
        run.stderr
    );
    assert_not_stored(&sb, &ops);
}
