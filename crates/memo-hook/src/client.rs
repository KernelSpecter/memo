//! In-process client: connects to memo's pipe, serializes messages, and guards
//! against hook reentrancy.

use core::cell::Cell;
use memo_proto::{write_msg, AccessKind, Msg, MutateKind, TaintReason};
use std::sync::{Mutex, OnceLock};
use windows_sys::Win32::Foundation::{
    CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_SHARE_MODE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Threading::GetCurrentProcessId;

thread_local! {
    static IN_HOOK: Cell<bool> = const { Cell::new(false) };
}

/// RAII reentrancy guard. `enter()` returns `None` if we're already inside a
/// hook on this thread (caller should just invoke the real function).
pub struct Guard;

pub fn enter() -> Option<Guard> {
    IN_HOOK.with(|f| {
        if f.get() {
            None
        } else {
            f.set(true);
            Some(Guard)
        }
    })
}

impl Drop for Guard {
    fn drop(&mut self) {
        IN_HOOK.with(|f| f.set(false));
    }
}

struct Client {
    pipe: HANDLE,
    pid: u32,
    seq: u64,
}

// SAFETY: access is always serialized through the Mutex.
unsafe impl Send for Client {}

static CLIENT: OnceLock<Mutex<Client>> = OnceLock::new();

/// Connect to memo's pipe and send the initial Hello. Returns false on failure
/// (the caller then leaves the process untraced; memo will taint via NoHello).
pub fn init(pipe_name: &str, image: &str) -> bool {
    let wide: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();
    let pipe = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0 as FILE_SHARE_MODE,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if pipe == INVALID_HANDLE_VALUE || pipe.is_null() {
        return false;
    }
    let pid = unsafe { GetCurrentProcessId() };
    let client = Client { pipe, pid, seq: 0 };
    if CLIENT.set(Mutex::new(client)).is_err() {
        // Already initialized (shouldn't happen); close the extra handle.
        unsafe { CloseHandle(pipe) };
        return false;
    }

    send(Msg::Hello {
        pid,
        ppid: 0,
        image: image.to_string(),
        loaded_modules: Vec::new(),
    });
    true
}

pub fn is_active() -> bool {
    CLIENT.get().is_some()
}

pub fn pid() -> u32 {
    // try_lock, not lock: this runs on hook paths (including DllMain's
    // DLL_PROCESS_DETACH), which must never block on a lock that a
    // now-gone thread may still hold during process teardown.
    CLIENT
        .get()
        .and_then(|m| m.try_lock().ok().map(|g| g.pid))
        .unwrap_or_else(|| unsafe { GetCurrentProcessId() })
}

fn write_all(pipe: HANDLE, bytes: &[u8]) -> bool {
    let mut off = 0usize;
    while off < bytes.len() {
        let mut written: u32 = 0;
        let ok = unsafe {
            WriteFile(
                pipe,
                bytes[off..].as_ptr(),
                (bytes.len() - off) as u32,
                &mut written,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || written == 0 {
            return false;
        }
        off += written as usize;
    }
    true
}

fn read_one_byte(pipe: HANDLE) -> bool {
    let mut b = [0u8; 1];
    let mut read: u32 = 0;
    let ok = unsafe { ReadFile(pipe, b.as_mut_ptr(), 1, &mut read, std::ptr::null_mut()) };
    ok != 0 && read == 1
}

/// Send a message (best-effort; pipe errors are swallowed — memo will notice
/// the process stopped reporting).
pub fn send(msg: Msg) {
    let cell = match CLIENT.get() {
        Some(c) => c,
        None => return,
    };
    let mut buf = Vec::with_capacity(64);
    if write_msg(&mut buf, &msg).is_err() {
        return;
    }
    // try_lock, not lock: a hook path (including DllMain's
    // DLL_PROCESS_DETACH) must never block waiting for this lock — if
    // another thread holds it (or held it and is now gone, during process
    // teardown), just drop the message rather than risk a deadlock.
    if let Ok(g) = cell.try_lock() {
        let _ = write_all(g.pipe, &buf);
    }
}

/// Report an access observation.
pub fn access(kind: AccessKind, path: String) {
    send(Msg::Access {
        pid: pid(),
        kind,
        path,
    });
}

/// Report a taint.
pub fn taint(reason: TaintReason, detail: &str) {
    send(Msg::Taint {
        pid: pid(),
        reason,
        detail: detail.to_string(),
    });
}

/// Report a mutation.
pub fn mutate(kind: MutateKind, path: String, target: Option<String>) {
    send(Msg::Mutate {
        pid: pid(),
        kind,
        path,
        target,
    });
}

/// Send a PreMutate for `path` and block until memo acknowledges (so memo has
/// snapshotted the pre-run state before the mutation happens). Best-effort: if
/// the pipe is gone, returns without blocking.
pub fn premutate_wait(path: String) {
    let cell = match CLIENT.get() {
        Some(c) => c,
        None => return,
    };
    if let Ok(mut g) = cell.lock() {
        g.seq += 1;
        let seq = g.seq;
        let pid = g.pid;
        let mut buf = Vec::with_capacity(64);
        if write_msg(&mut buf, &Msg::PreMutate { pid, seq, path }).is_err() {
            return;
        }
        if write_all(g.pipe, &buf) {
            // Block for the single ack byte while holding the lock so this
            // process sends nothing else until the snapshot is taken.
            let _ = read_one_byte(g.pipe);
        }
    }
}

/// Report the child spawn.
pub fn child_spawned(child_pid: u32, injected: bool) {
    send(Msg::ChildSpawned {
        pid: pid(),
        child_pid,
        injected,
    });
}

/// Send Bye on process detach.
pub fn bye(exit_ok: bool) {
    send(Msg::Bye {
        pid: pid(),
        exit_ok,
    });
}
