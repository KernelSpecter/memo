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
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
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

/// Resolved address of `ntdll!RtlDllShutdownInProgress` (0 if it couldn't be
/// resolved), looked up once. Stored as an address rather than a typed fn
/// pointer so it fits in a plain `OnceLock` without unsafe Send/Sync impls.
static RTL_DLL_SHUTDOWN_IN_PROGRESS_ADDR: OnceLock<usize> = OnceLock::new();

/// True only once the process is actually tearing itself down — past
/// `ExitProcess`'s point of no return, where other threads may already be
/// gone (possibly while still holding `CLIENT`'s lock) — as opposed to, say,
/// some *other* DLL in the process calling `FreeLibrary` on itself, which is
/// normal operation for everyone else.
///
/// `RtlDllShutdownInProgress` is an undocumented but long-stable ntdll
/// export (present since NT4; confirmed present in this environment's
/// ntdll.dll). It's resolved via `GetModuleHandleW`/`GetProcAddress` — the
/// same pattern `hooks.rs` already uses for the real NT-API trampolines —
/// and cached: `GetModuleHandleW("ntdll.dll")` never fails (ntdll is loaded
/// in every process) and neither call blocks. If the export still can't be
/// resolved for some reason, this fails safe to `false`: callers then take
/// the normal, blocking path (never silently dropping a message) rather than
/// the teardown-only non-blocking one.
fn shutting_down() -> bool {
    let addr = *RTL_DLL_SHUTDOWN_IN_PROGRESS_ADDR.get_or_init(|| unsafe {
        let name: Vec<u16> = "ntdll.dll"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let ntdll = GetModuleHandleW(name.as_ptr());
        if ntdll.is_null() {
            return 0;
        }
        crate::hooks::proc_addr(ntdll, "RtlDllShutdownInProgress") as usize
    });
    if addr == 0 {
        return false;
    }
    type RtlDllShutdownInProgressFn = unsafe extern "system" fn() -> u8;
    let f: RtlDllShutdownInProgressFn = unsafe { core::mem::transmute(addr as *const ()) };
    unsafe { f() != 0 }
}

/// Lock `m`, blocking normally so a message is never silently dropped in
/// normal operation — except once the process is actually tearing itself
/// down (see `shutting_down`). At that point every other thread has already
/// been terminated, so a lock still held can only belong to a thread that no
/// longer exists to release it: blocking would deadlock forever, and the
/// message would be lost either way (blocked or dropped). A non-blocking
/// `try_lock` there is strictly better: same outcome for the message, no
/// deadlock.
fn lock(m: &Mutex<Client>) -> Option<std::sync::MutexGuard<'_, Client>> {
    if shutting_down() {
        m.try_lock().ok()
    } else {
        m.lock().ok()
    }
}

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
    CLIENT
        .get()
        .and_then(|m| lock(m).map(|g| g.pid))
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
    if let Some(g) = lock(cell) {
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
    // During process teardown, skip the snapshot handshake entirely: don't
    // lock, don't send, don't wait for the ack. A mutation observed during
    // teardown is never cached anyway (the run is ending and memo's pipe
    // server is gone), so there's nothing worth blocking for -- and blocking
    // here is exactly the C5 hang class this task closes: CLIENT may be held
    // by a thread that no longer exists (deadlock on the lock itself), or
    // memo's server may already be gone (deadlock waiting for an ack that
    // will never arrive). The normal (not shutting down) path is unchanged:
    // it must still block for the ack so the snapshot precedes the mutation.
    if shutting_down() {
        return;
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// If `GetProcAddress` ever failed to resolve `RtlDllShutdownInProgress`,
    /// `shutting_down()` would silently and permanently return `false`
    /// (fail-safe to "block normally", per its doc comment) and nothing
    /// would notice. Assert the resolution actually succeeds, and that a
    /// perfectly normal test process (not shutting down) reports `false`.
    #[test]
    fn rtl_dll_shutdown_in_progress_resolves_and_is_false_here() {
        assert!(
            !shutting_down(),
            "this test process is not shutting down, so this must be false"
        );
        let addr = *RTL_DLL_SHUTDOWN_IN_PROGRESS_ADDR
            .get()
            .expect("shutting_down() above must have resolved and cached the address");
        assert_ne!(
            addr, 0,
            "RtlDllShutdownInProgress must resolve to a real ntdll export, \
             not the unresolved-export (0) fallback"
        );
    }
}
