//! Regression test for C5: a hooked process that exits abruptly while other
//! threads are still live and mid file-I/O must never hang memo.
//!
//! Before the fix, `memo_hook`'s `DllMain` called `client::bye` on every
//! `DLL_PROCESS_DETACH`, which locks the client mutex. At `ExitProcess` time
//! the loader lock is held and other threads may already be gone (possibly
//! while holding that same mutex), so this could deadlock — and memo waited
//! on the child with an `INFINITE` `WaitForSingleObject`, so the user's
//! command never returned.
//!
//! This is inherently timing-based (the hang depends on winning a race), so
//! it's made robust by repeating many times, each individually bounded: if
//! the fix works, all iterations finish quickly; if the bug is present, at
//! least some iterations are expected to hang until their bound is hit.

mod it_util;
use it_util::{memo_exe, probe_exe, Sandbox};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const ITERATIONS: usize = 25;
const PER_RUN_TIMEOUT: Duration = Duration::from_secs(15);

/// Terminate `root_pid` and every descendant process found in a fresh process
/// snapshot, walked ourselves rather than trusting `taskkill /T`: observed
/// directly against this bug, `taskkill /F /T` found the deadlocked
/// memo-probe.exe (reporting it as a child of the memo.exe pid) but its
/// TerminateProcess call was refused — "could not be terminated" — plausibly
/// because the probe was already inside `ExitProcess`, which can briefly make
/// a process resist termination. Left running, that child keeps
/// memo_hook.dll and memo-probe.exe open and a later `cargo build` can't
/// relink them.
///
/// Returns the number of descendants (excluding `root_pid` itself) found in
/// this call's snapshot, so callers can retry until that reaches zero rather
/// than trusting a single attempt to have worked.
fn kill_tree(root_pid: u32) -> usize {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE || snap.is_null() {
            return 0;
        }
        let mut entries: Vec<(u32, u32)> = Vec::new();
        let mut entry: PROCESSENTRY32W = core::mem::zeroed();
        entry.dwSize = core::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap, &mut entry) != 0 {
            loop {
                entries.push((entry.th32ProcessID, entry.th32ParentProcessID));
                if Process32NextW(snap, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);

        // BFS out from root_pid over the (pid, parent_pid) snapshot to find
        // every descendant, then kill root + descendants directly by pid.
        let mut to_kill = vec![root_pid];
        let mut frontier = vec![root_pid];
        while let Some(parent) = frontier.pop() {
            for &(pid, ppid) in &entries {
                if ppid == parent && !to_kill.contains(&pid) {
                    to_kill.push(pid);
                    frontier.push(pid);
                }
            }
        }
        let descendant_count = to_kill.len() - 1;
        for pid in to_kill {
            let h = OpenProcess(PROCESS_TERMINATE, 0, pid);
            if !h.is_null() {
                TerminateProcess(h, 1);
                CloseHandle(h);
            }
        }
        descendant_count
    }
}

#[test]
fn abrupt_exit_with_live_threads_does_not_hang() {
    for i in 0..ITERATIONS {
        // A fresh cache per iteration: reusing one MEMO_DIR would replay the
        // first run's result from cache on every later iteration (same
        // command, same env, same cwd), so only iteration 0 would ever
        // actually execute the probe.
        let sb = Sandbox::new(&format!("exit_hang_{i}"));

        let mut cmd = Command::new(memo_exe());
        cmd.current_dir(&sb.work);
        cmd.env("MEMO_DIR", &sb.cache);
        cmd.env("MEMO_PROBE_MARKER", &sb.marker);
        cmd.env("MEMO_FORCE_STATUS", "1");
        cmd.arg(probe_exe());
        cmd.arg("threads=8");
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::null());

        let before = sb.marker_count();
        let mut child = cmd.spawn().expect("spawn memo");

        // std has no `wait_timeout`; poll `try_wait` against a deadline.
        let deadline = Instant::now() + PER_RUN_TIMEOUT;
        let status = loop {
            if let Some(status) = child.try_wait().expect("try_wait") {
                break Some(status);
            }
            if Instant::now() >= deadline {
                break None;
            }
            std::thread::sleep(Duration::from_millis(50));
        };

        let status = match status {
            Some(status) => status,
            None => {
                // Hung: kill the whole tree by pid. memo.exe (the parent)
                // typically exits almost immediately once killed, but
                // memo-probe.exe (the child actually deadlocked inside
                // DllMain) can resist TerminateProcess for a moment — so
                // retry by descendant count from a fresh snapshot each time,
                // not by whether memo.exe itself has exited.
                let pid = child.id();
                for _ in 0..25 {
                    if kill_tree(pid) == 0 {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(200));
                }
                let _ = child.wait();
                panic!(
                    "iteration {i}: memo did not exit within {PER_RUN_TIMEOUT:?} (hang in DllMain detach)"
                );
            }
        };

        let after = sb.marker_count();
        assert!(
            status.success(),
            "iteration {i}: memo exited with {status:?}"
        );
        assert_eq!(
            after - before,
            1,
            "iteration {i}: probe did not execute for real (expected one execution)"
        );
    }
}
