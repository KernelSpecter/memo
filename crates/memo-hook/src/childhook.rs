//! Child-process creation hooks: create the child suspended, inject
//! memo_hook.dll and the run payload, then resume — so every descendant is
//! traced. A child we cannot inject (WOW64, or injection failure) is tainted so
//! the run stays uncacheable.

use crate::client;
use core::ffi::c_void;
use core::panic::AssertUnwindSafe;
use memo_detours::{DetourCopyPayloadToProcess, DetourUpdateProcessWithDll, MEMO_GUID};
use memo_proto::{RunPayload, TaintReason};
use std::panic::catch_unwind;
use windows_sys::core::{PCSTR, PWSTR};
use windows_sys::Win32::Foundation::{BOOL, HANDLE};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::Threading::{
    IsWow64Process2, ResumeThread, PROCESS_INFORMATION, STARTUPINFOW,
};

const CREATE_SUSPENDED: u32 = 0x0000_0004;
const IMAGE_FILE_MACHINE_UNKNOWN: u16 = 0;

static mut REAL_CREATEPROCESSW: *mut c_void = std::ptr::null_mut();
static mut REAL_CREATEPROCESSA: *mut c_void = std::ptr::null_mut();
static mut REAL_CREATEPROCESSASUSERW: *mut c_void = std::ptr::null_mut();

type CreateProcessWFn = unsafe extern "system" fn(
    *const u16,
    PWSTR,
    *const SECURITY_ATTRIBUTES,
    *const SECURITY_ATTRIBUTES,
    BOOL,
    u32,
    *const c_void,
    *const u16,
    *const STARTUPINFOW,
    *mut PROCESS_INFORMATION,
) -> BOOL;

type CreateProcessAFn = unsafe extern "system" fn(
    *const u8,
    *mut u8,
    *const SECURITY_ATTRIBUTES,
    *const SECURITY_ATTRIBUTES,
    BOOL,
    u32,
    *const c_void,
    *const u8,
    *const c_void, // STARTUPINFOA
    *mut PROCESS_INFORMATION,
) -> BOOL;

type CreateProcessAsUserWFn = unsafe extern "system" fn(
    HANDLE,
    *const u16,
    PWSTR,
    *const SECURITY_ATTRIBUTES,
    *const SECURITY_ATTRIBUTES,
    BOOL,
    u32,
    *const c_void,
    *const u16,
    *const STARTUPINFOW,
    *mut PROCESS_INFORMATION,
) -> BOOL;

/// Inject our DLL + payload into a freshly created, suspended child process.
unsafe fn inject(h_process: HANDLE) -> bool {
    let dll = match crate::self_module_path() {
        Some(p) => p,
        None => return false,
    };
    // DetourUpdateProcessWithDll takes ANSI paths. Our install path is ASCII;
    // if not, injection fails and the caller taints (still correct).
    let ansi: Vec<u8> = dll.bytes().chain(std::iter::once(0)).collect();
    let dll_ptr: PCSTR = ansi.as_ptr();
    let dlls = [dll_ptr];
    if DetourUpdateProcessWithDll(h_process, dlls.as_ptr(), 1) == 0 {
        return false;
    }
    let pl: &RunPayload = match crate::payload() {
        Some(p) => p,
        None => return false,
    };
    DetourCopyPayloadToProcess(
        h_process,
        &MEMO_GUID,
        pl.as_bytes().as_ptr() as *const c_void,
        core::mem::size_of::<RunPayload>() as u32,
    ) != 0
}

/// Handle a created child: inject unless WOW64, report, resume unless the caller
/// asked for a suspended child.
unsafe fn handle_child(h_process: HANDLE, h_thread: HANDLE, child_pid: u32, original_flags: u32) {
    let mut process_machine: u16 = 0;
    let mut native_machine: u16 = 0;
    let wow64 = IsWow64Process2(h_process, &mut process_machine, &mut native_machine) != 0
        && process_machine != IMAGE_FILE_MACHINE_UNKNOWN;

    if wow64 {
        client::child_spawned(child_pid, false);
        client::taint(TaintReason::Wow64Child, "32-bit child process");
    } else {
        let injected = inject(h_process);
        client::child_spawned(child_pid, injected);
        if !injected {
            client::taint(TaintReason::InjectFailed, "could not inject child");
        }
    }

    if original_flags & CREATE_SUSPENDED == 0 {
        ResumeThread(h_thread);
    }
}

unsafe extern "system" fn h_createprocessw(
    app: *const u16,
    cmd: PWSTR,
    pa: *const SECURITY_ATTRIBUTES,
    ta: *const SECURITY_ATTRIBUTES,
    inherit: BOOL,
    flags: u32,
    env: *const c_void,
    dir: *const u16,
    si: *const STARTUPINFOW,
    pi: *mut PROCESS_INFORMATION,
) -> BOOL {
    let real: CreateProcessWFn = core::mem::transmute(REAL_CREATEPROCESSW);
    let guard = client::enter();
    if guard.is_none() {
        return real(app, cmd, pa, ta, inherit, flags, env, dir, si, pi);
    }
    let ok = real(
        app,
        cmd,
        pa,
        ta,
        inherit,
        flags | CREATE_SUSPENDED,
        env,
        dir,
        si,
        pi,
    );
    if ok == 0 {
        let e = windows_sys::Win32::Foundation::GetLastError();
        client::taint(
            TaintReason::InternalError,
            &format!("CreateProcessW failed err={}", e),
        );
        return ok;
    }
    if !pi.is_null() {
        let info = &*pi;
        let (hp, ht, id) = (info.hProcess, info.hThread, info.dwProcessId);
        let _ = catch_unwind(AssertUnwindSafe(|| handle_child(hp, ht, id, flags)));
    }
    ok
}

unsafe extern "system" fn h_createprocessa(
    app: *const u8,
    cmd: *mut u8,
    pa: *const SECURITY_ATTRIBUTES,
    ta: *const SECURITY_ATTRIBUTES,
    inherit: BOOL,
    flags: u32,
    env: *const c_void,
    dir: *const u8,
    si: *const c_void,
    pi: *mut PROCESS_INFORMATION,
) -> BOOL {
    let real: CreateProcessAFn = core::mem::transmute(REAL_CREATEPROCESSA);
    let guard = client::enter();
    if guard.is_none() {
        return real(app, cmd, pa, ta, inherit, flags, env, dir, si, pi);
    }
    let ok = real(
        app,
        cmd,
        pa,
        ta,
        inherit,
        flags | CREATE_SUSPENDED,
        env,
        dir,
        si,
        pi,
    );
    if ok != 0 && !pi.is_null() {
        let info = &*pi;
        let (hp, ht, id) = (info.hProcess, info.hThread, info.dwProcessId);
        let _ = catch_unwind(AssertUnwindSafe(|| handle_child(hp, ht, id, flags)));
    }
    ok
}

#[allow(clippy::too_many_arguments)]
unsafe extern "system" fn h_createprocessasuserw(
    token: HANDLE,
    app: *const u16,
    cmd: PWSTR,
    pa: *const SECURITY_ATTRIBUTES,
    ta: *const SECURITY_ATTRIBUTES,
    inherit: BOOL,
    flags: u32,
    env: *const c_void,
    dir: *const u16,
    si: *const STARTUPINFOW,
    pi: *mut PROCESS_INFORMATION,
) -> BOOL {
    let real: CreateProcessAsUserWFn = core::mem::transmute(REAL_CREATEPROCESSASUSERW);
    let guard = client::enter();
    if guard.is_none() {
        return real(token, app, cmd, pa, ta, inherit, flags, env, dir, si, pi);
    }
    let ok = real(
        token,
        app,
        cmd,
        pa,
        ta,
        inherit,
        flags | CREATE_SUSPENDED,
        env,
        dir,
        si,
        pi,
    );
    if ok != 0 && !pi.is_null() {
        let info = &*pi;
        let (hp, ht, id) = (info.hProcess, info.hThread, info.dwProcessId);
        let _ = catch_unwind(AssertUnwindSafe(|| handle_child(hp, ht, id, flags)));
    }
    ok
}

unsafe fn proc_addr(module: *mut c_void, name: &str) -> *mut c_void {
    let cname: Vec<u8> = name.bytes().chain(std::iter::once(0)).collect();
    match GetProcAddress(module as _, cname.as_ptr()) {
        Some(f) => f as *mut c_void,
        None => std::ptr::null_mut(),
    }
}

/// Attach CreateProcess* hooks. Called inside the install() Detours transaction.
pub unsafe fn attach_child_hooks() {
    let k32_name: Vec<u16> = "kernel32.dll"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let k32 = GetModuleHandleW(k32_name.as_ptr());
    if k32.is_null() {
        return;
    }

    REAL_CREATEPROCESSW = proc_addr(k32, "CreateProcessW");
    REAL_CREATEPROCESSA = proc_addr(k32, "CreateProcessA");
    REAL_CREATEPROCESSASUSERW = proc_addr(k32, "CreateProcessAsUserW");

    if !REAL_CREATEPROCESSW.is_null() {
        memo_detours::DetourAttach(
            std::ptr::addr_of_mut!(REAL_CREATEPROCESSW),
            h_createprocessw as *const () as *mut c_void,
        );
    }
    if !REAL_CREATEPROCESSA.is_null() {
        memo_detours::DetourAttach(
            std::ptr::addr_of_mut!(REAL_CREATEPROCESSA),
            h_createprocessa as *const () as *mut c_void,
        );
    }
    if !REAL_CREATEPROCESSASUSERW.is_null() {
        memo_detours::DetourAttach(
            std::ptr::addr_of_mut!(REAL_CREATEPROCESSASUSERW),
            h_createprocessasuserw as *const () as *mut c_void,
        );
    }
}
