//! Replay reproduces stdout, stderr, and the exit code faithfully.

mod it_util;
use it_util::Sandbox;

#[test]
fn stdout_stderr_and_exit_are_replayed() {
    let sb = Sandbox::new("replay_fidelity");
    let ops = ["print=alpha", "eprint=beta", "print=gamma", "exit=0"];

    let r1 = sb.run(&ops);
    assert!(r1.executed);
    assert!(r1.cached(), "stderr: {}", r1.stderr);
    assert!(r1.stdout.contains("alpha"));
    assert!(r1.stdout.contains("gamma"));
    assert!(r1.stderr.contains("beta"));

    let r2 = sb.run(&ops);
    assert!(r2.replayed(), "stderr: {}", r2.stderr);
    assert!(!r2.executed);
    assert_eq!(r1.stdout, r2.stdout, "replayed stdout must match exactly");
    // r2.stderr also contains memo's status line; check the program output is present.
    assert!(
        r2.stderr.contains("beta"),
        "replayed stderr must include program output"
    );
}

#[test]
fn nonzero_exit_code_replayed_with_cache_failures() {
    let sb = Sandbox::new("replay_exit");
    let r1 = sb.run_with_flags(&["--cache-failures"], &["print=x", "exit=42"]);
    assert_eq!(r1.exit, 42);
    assert!(r1.cached(), "stderr: {}", r1.stderr);

    let r2 = sb.run_with_flags(&["--cache-failures"], &["print=x", "exit=42"]);
    assert!(r2.replayed(), "stderr: {}", r2.stderr);
    assert_eq!(r2.exit, 42, "replayed exit code must match");
}
