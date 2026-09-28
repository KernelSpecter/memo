//! Ctrl+C reporting (spec §10). memo marks an interrupted run uncacheable, but
//! its own console handler may run only after the command has already handled
//! the event and exited 0. So every traced process reports the event itself,
//! from a handler kept at the head of its handler list: handlers are called
//! last-registered first, so ours runs before the app's, sends the taint
//! synchronously (it is in the pipe before the process can exit), and returns
//! FALSE so the app's own handlers run exactly as they would without memo.

use crate::client;
use core::ffi::c_void;
use memo_proto::TaintReason;
use std::panic::{catch_unwind, AssertUnwindSafe};
use windows_sys::Win32::Foundation::BOOL;
use windows_sys::Win32::System::Console::PHANDLER_ROUTINE;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;

type SetConsoleCtrlHandlerFn = unsafe extern "system" fn(PHANDLER_ROUTINE, BOOL) -> BOOL;

static mut REAL_SETCONSOLECTRLHANDLER: *mut c_void = std::ptr::null_mut();

unsafe extern "system" fn report_ctrl(ctrl: u32) -> BOOL {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if let Some(_g) = client::enter() {
            let detail = format!(
                "console control event {} in pid {}",
                ctrl,
                std::process::id()
            );
            client::taint(TaintReason::Interrupted, &detail);
        }
    }));
    0
}

unsafe extern "system" fn h_setconsolectrlhandler(handler: PHANDLER_ROUTINE, add: BOOL) -> BOOL {
    let real: SetConsoleCtrlHandlerFn = core::mem::transmute(REAL_SETCONSOLECTRLHANDLER);
    let r = real(handler, add);
    // An app handler was just added at the head: move ours back in front.
    // (A NULL handler toggles the ignore-Ctrl+C flag and adds nothing.)
    if r != 0 && add != 0 && handler.is_some() {
        real(Some(report_ctrl), 0);
        real(Some(report_ctrl), 1);
    }
    r
}

/// Queue the detour; call inside the hooks' Detours transaction. kernelbase,
/// not kernel32: the UCRT (e.g. Python's signal module) calls it through API
/// sets that resolve straight to kernelbase, and kernel32's export jumps there.
pub unsafe fn attach() {
    let name: Vec<u16> = "kernelbase.dll"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let kb = GetModuleHandleW(name.as_ptr());
    if kb.is_null() {
        return;
    }
    REAL_SETCONSOLECTRLHANDLER = crate::hooks::proc_addr(kb, "SetConsoleCtrlHandler");
    if !REAL_SETCONSOLECTRLHANDLER.is_null() {
        memo_detours::DetourAttach(
            std::ptr::addr_of_mut!(REAL_SETCONSOLECTRLHANDLER),
            h_setconsolectrlhandler as *const () as *mut c_void,
        );
    }
}

/// Register the reporting handler; call after the transaction commits, so the
/// real pointer is the trampoline.
pub unsafe fn register() {
    if REAL_SETCONSOLECTRLHANDLER.is_null() {
        return;
    }
    let real: SetConsoleCtrlHandlerFn = core::mem::transmute(REAL_SETCONSOLECTRLHANDLER);
    real(Some(report_ctrl), 1);
}
