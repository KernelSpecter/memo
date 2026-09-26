//! Runs that touch the network, or fail, are not cached (unless opted in).

mod it_util;
use it_util::{abs, Sandbox};

#[test]
fn network_access_is_not_cached() {
    let sb = Sandbox::new("taint_net");
    // Connect to a port on localhost (likely closed); the connect syscall is
    // what taints, regardless of success.
    let r1 = sb.run(&["net=127.0.0.1:9"]);
    assert_eq!(r1.exit, 0, "stderr: {}", r1.stderr);
    assert!(
        r1.not_cached(),
        "network run must not be cached; stderr: {}",
        r1.stderr
    );

    // Because it wasn't cached, the next run executes again.
    let r2 = sb.run(&["net=127.0.0.1:9"]);
    assert!(r2.executed, "stderr: {}", r2.stderr);
}

#[test]
fn network_cached_with_allow_flag() {
    let sb = Sandbox::new("taint_net_allow");
    let r1 = sb.run_with_flags(&["--allow-network"], &["net=127.0.0.1:9"]);
    assert!(
        r1.cached(),
        "with --allow-network it should cache; stderr: {}",
        r1.stderr
    );
    let r2 = sb.run_with_flags(&["--allow-network"], &["net=127.0.0.1:9"]);
    assert!(r2.replayed(), "stderr: {}", r2.stderr);
}

#[test]
fn nonzero_exit_not_cached_by_default() {
    let sb = Sandbox::new("taint_exit");
    sb.write("a.txt", b"x");
    let a = abs(&sb.path("a.txt"));
    let ops = [format!("read={}", a), "exit=3".to_string()];
    let ops_ref: Vec<&str> = ops.iter().map(|s| s.as_str()).collect();

    let r1 = sb.run(&ops_ref);
    assert_eq!(r1.exit, 3);
    assert!(r1.not_cached(), "stderr: {}", r1.stderr);

    // --cache-failures caches it and replays the exit code.
    let r2 = sb.run_with_flags(&["--cache-failures"], &ops_ref);
    assert_eq!(r2.exit, 3);
    assert!(r2.cached(), "stderr: {}", r2.stderr);
    let r3 = sb.run_with_flags(&["--cache-failures"], &ops_ref);
    assert!(r3.replayed(), "stderr: {}", r3.stderr);
    assert_eq!(r3.exit, 3, "replayed exit code must match");
}
