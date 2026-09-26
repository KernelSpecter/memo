//! memo_hook.dll — injected by memo into every traced process. Connects to
//! memo's pipe and intercepts file I/O to report inputs and outputs.

#![allow(non_snake_case)]

mod childhook;
mod client;
mod hooks;
mod ntdef;
mod pathres;

use core::ffi::c_void;
use memo_detours::{DetourFindPayloadEx, DetourIsHelperProcess, DetourRestoreAfterWith, MEMO_GUID};
use memo_proto::RunPayload;
use std::sync::OnceLock;
use windows_sys::Win32::Foundation::{BOOL, HANDLE, HMODULE, TRUE};
use windows_sys::Win32::System::LibraryLoader::{DisableThreadLibraryCalls, GetModuleFileNameW};
use windows_sys::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};

/// This DLL's own module handle, saved so child injection can find its path.
static SELF_MODULE: OnceLock<usize> = OnceLock::new();

pub(crate) fn self_module_path() -> Option<String> {
    let h = *SELF_MODULE.get()? as HMODULE;
    let mut buf = [0u16; 1024];
    let n = unsafe { GetModuleFileNameW(h, buf.as_mut_ptr(), buf.len() as u32) };
    if n == 0 {
        return None;
    }
    Some(String::from_utf16_lossy(&buf[..n as usize]))
}

fn current_image_path() -> String {
    let mut buf = [0u16; 1024];
    let n = unsafe { GetModuleFileNameW(0 as HMODULE, buf.as_mut_ptr(), buf.len() as u32) };
    if n == 0 {
        String::new()
    } else {
        String::from_utf16_lossy(&buf[..n as usize])
    }
}

#[no_mangle]
pub extern "system" fn DllMain(hinst: HMODULE, reason: u32, _reserved: *mut c_void) -> BOOL {
    match reason {
        DLL_PROCESS_ATTACH => {
            let _ = std::panic::catch_unwind(|| on_attach(hinst));
        }
        DLL_PROCESS_DETACH => {
            let _ = std::panic::catch_unwind(|| {
                if client::is_active() {
                    client::bye(true);
                }
            });
        }
        _ => {}
    }
    TRUE
}

fn on_attach(hinst: HMODULE) {
    unsafe { DisableThreadLibraryCalls(hinst) };
    let _ = SELF_MODULE.set(hinst as usize);

    // If we're the Detours helper process, do nothing else.
    if unsafe { DetourIsHelperProcess() } != 0 {
        return;
    }
    unsafe { DetourRestoreAfterWith() };

    // Find memo's payload. If absent, this DLL was loaded outside memo.
    let mut cb: u32 = 0;
    let payload = unsafe { DetourFindPayloadEx(&MEMO_GUID, &mut cb) };
    if payload.is_null() || (cb as usize) < core::mem::size_of::<RunPayload>() {
        return;
    }
    let bytes = unsafe {
        std::slice::from_raw_parts(payload as *const u8, core::mem::size_of::<RunPayload>())
    };
    let rp = match RunPayload::from_bytes(bytes) {
        Some(p) => p,
        None => return,
    };
    let pipe_name = rp.pipe_name_string();
    let image = current_image_path();

    if client::init(&pipe_name, &image) {
        hooks::install();
    }
}

// DetourFinishHelperProcess is provided by the vendored Detours static library
// and exported at ordinal 1 via src/exports.def (the .def entry forces the
// linker to pull it in). We must NOT define our own — that would be a duplicate
// symbol.

/// Force the linker to retain the Detours helper symbol by referencing it.
#[used]
static _KEEP_FINISH: memo_detours::FinishHelperProc = memo_detours::DetourFinishHelperProcess;

/// Silence unused warning for HANDLE re-export used by submodules' signatures.
#[allow(dead_code)]
type _Handle = HANDLE;
