//! I4: when tracing can't be set up (here: the hook DLL is missing), memo runs
//! the command normally and doesn't cache it (spec §10) — it does not exit 125
//! without running the command.

mod it_util;
use it_util::{abs, Sandbox};

#[test]
fn missing_hook_dll_runs_untraced() {
    let sb = Sandbox::new("untraced");
    let out = abs(&sb.path("made.txt"));
    let op = format!("write={}|by-untraced-run", out);

    // Point the hook DLL at a path that doesn't exist so tracing setup fails.
    let env = [("MEMO_HOOK_DLL", "C:\\memo-does-not-exist\\memo_hook.dll")];
    let r = sb.run_with_env(&["-v"], &env, &[&op]);

    assert_eq!(
        r.exit, 0,
        "the command's own exit code must be returned; stderr: {}",
        r.stderr
    );
    assert!(
        r.executed,
        "the command must actually run; stderr: {}",
        r.stderr
    );
    assert!(
        r.not_cached(),
        "an untraced run must not be cached; stderr: {}",
        r.stderr
    );
    assert_eq!(
        std::fs::read(sb.path("made.txt")).unwrap(),
        b"by-untraced-run",
        "the untraced command's output must be produced"
    );
}
