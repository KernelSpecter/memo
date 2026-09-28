//! Regression test for the RtlDllShutdownInProgress-gated lock in
//! `memo_hook::client`: `send`/`pid` must block normally (never silently
//! drop a message) during ordinary, non-teardown operation, even under real
//! multithreaded contention on the CLIENT mutex.
//!
//! Round 1 of this task made `send`/`pid` use an unconditional `try_lock`,
//! which is safe against the DllMain-detach hang but can drop a message any
//! time two threads in the same hooked process contend the lock — including
//! in completely normal, non-exiting runs (e.g. while `premutate_wait` holds
//! the lock across its ack round-trip with memo). Round 2 gates the
//! non-blocking path on `RtlDllShutdownInProgress`, so normal operation
//! should always block instead of dropping.
//!
//! The probe's `mtio=<in>|<out>` op races a writer thread (50 writes to
//! <out>, each held across a premutate_wait ack round-trip) against exactly
//! one read of <in> from the main thread, timed to land while the writer is
//! still going. If that single Access::Read for <in> were ever dropped,
//! memo would never record <in> as an input, and changing <in> afterward
//! would wrongly replay from cache (a stale hit) instead of forcing a real
//! re-run (a correct miss).

mod it_util;
use it_util::{abs, Sandbox};
use std::time::Duration;

const ITERATIONS: usize = 10;

#[test]
fn concurrent_read_is_never_dropped_as_an_input() {
    for i in 0..ITERATIONS {
        let sb = Sandbox::new(&format!("mtio_no_drop_{i}"));
        sb.write("in.txt", b"one");
        let in_path = abs(&sb.path("in.txt"));
        let out_path = abs(&sb.path("out.txt"));
        let op = format!("mtio={}|{}", in_path, out_path);

        let r1 = sb.run(&[&op]);
        assert_eq!(r1.exit, 0, "iteration {i}: run 1 stderr: {}", r1.stderr);
        assert!(
            r1.executed,
            "iteration {i}: run 1 must execute for real; stderr: {}",
            r1.stderr
        );

        // Change the tracked input: the next run must miss and re-execute,
        // unless the single Access::Read for in.txt got dropped by a
        // contended CLIENT lock, in which case memo never recorded it as an
        // input and this would wrongly replay from cache instead.
        std::thread::sleep(Duration::from_millis(20));
        sb.write("in.txt", b"two-different");

        let r2 = sb.run(&[&op]);
        assert_eq!(r2.exit, 0, "iteration {i}: run 2 stderr: {}", r2.stderr);
        assert!(
            r2.executed,
            "iteration {i}: changed input must force real execution -- a \
             dropped Access message would replay stale instead; stderr: {}",
            r2.stderr
        );
    }
}
