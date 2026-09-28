//! I2: arguments to a .cmd/.bat shim must not inject cmd commands. Run a real
//! .cmd through memo with a redirection metacharacter in an argument; if the
//! escaping is wrong, cmd performs the redirection and creates a file.

mod it_util;
use it_util::{abs, Sandbox};

#[test]
fn cmd_argument_cannot_inject_redirection() {
    let sb = Sandbox::new("cmd_inject");
    // A trivial batch file that just succeeds.
    sb.write("run.cmd", b"@echo off\r\necho ok\r\n");
    let script = abs(&sb.path("run.cmd"));

    // If `>pwned.txt` leaks to cmd, it redirects output into pwned.txt.
    let r = sb.subcommand(&[&script, "harmless>pwned.txt"]);
    assert_eq!(r.exit, 0, "stderr: {}", r.stderr);
    assert!(
        !sb.path("pwned.txt").exists(),
        "redirection metacharacter in an argument must not be acted on by cmd"
    );

    // And `&` must not chain a second command.
    let r2 = sb.subcommand(&[&script, "a&echo z>pwned2.txt"]);
    assert_eq!(r2.exit, 0, "stderr: {}", r2.stderr);
    assert!(
        !sb.path("pwned2.txt").exists(),
        "command-chaining metacharacter in an argument must not run a second command"
    );
}
