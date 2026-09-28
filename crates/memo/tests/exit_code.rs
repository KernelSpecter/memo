//! memo returns the command's real exit code, including values above 255 (which
//! don't fit in std's ExitCode).

mod it_util;
use it_util::Sandbox;

#[test]
fn small_exit_code_is_returned() {
    let sb = Sandbox::new("exit_small");
    let r = sb.run(&["exit=7"]);
    assert_eq!(r.exit, 7, "stderr: {}", r.stderr);
}

#[test]
fn exit_code_above_255_is_preserved() {
    let sb = Sandbox::new("exit_big");
    let r = sb.run(&["exit=300"]);
    assert_eq!(
        r.exit, 300,
        "exit codes above 255 must not be clamped; stderr: {}",
        r.stderr
    );
}
