//! Minimal Rust bindings to the vendored Microsoft Detours library.
//!
//! Only the functions memo actually uses are declared. The C++ sources are
//! compiled by `build.rs` into a static `detours` library and linked here.

#![allow(non_snake_case)]

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{BOOL, HANDLE, HMODULE, HWND};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::System::Threading::{
    PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTUPINFOW,
};

/// GUID identifying memo's payload inside an injected process. Fixed constant;
/// the hook DLL looks this up with `DetourFindPayloadEx`.
pub const MEMO_GUID: GUID = GUID {
    data1: 0x6D656D6F,
    data2: 0x0001,
    data3: 0x4D45,
    data4: [0x4D, 0x4F, 0x72, 0x75, 0x6E, 0x70, 0x61, 0x79],
};

// C signature: VOID CALLBACK DetourFinishHelperProcess(HWND, HINSTANCE, LPSTR, INT)
pub type FinishHelperProc = unsafe extern "system" fn(HWND, HMODULE, windows_sys::core::PSTR, i32);

extern "system" {
    pub fn DetourIsHelperProcess() -> BOOL;
    pub fn DetourRestoreAfterWith() -> BOOL;

    pub fn DetourTransactionBegin() -> i32;
    pub fn DetourTransactionAbort() -> i32;
    pub fn DetourTransactionCommit() -> i32;
    pub fn DetourUpdateThread(hThread: HANDLE) -> i32;

    pub fn DetourAttach(
        ppPointer: *mut *mut core::ffi::c_void,
        pDetour: *mut core::ffi::c_void,
    ) -> i32;
    pub fn DetourDetach(
        ppPointer: *mut *mut core::ffi::c_void,
        pDetour: *mut core::ffi::c_void,
    ) -> i32;

    pub fn DetourFindPayloadEx(rguid: *const GUID, pcbData: *mut u32) -> *mut core::ffi::c_void;

    pub fn DetourCreateProcessWithDllExW(
        lpApplicationName: windows_sys::core::PCWSTR,
        lpCommandLine: windows_sys::core::PWSTR,
        lpProcessAttributes: *const SECURITY_ATTRIBUTES,
        lpThreadAttributes: *const SECURITY_ATTRIBUTES,
        bInheritHandles: BOOL,
        dwCreationFlags: PROCESS_CREATION_FLAGS,
        lpEnvironment: *const core::ffi::c_void,
        lpCurrentDirectory: windows_sys::core::PCWSTR,
        lpStartupInfo: *const STARTUPINFOW,
        lpProcessInformation: *mut PROCESS_INFORMATION,
        lpDllName: windows_sys::core::PCSTR,
        pfCreateProcessW: *mut core::ffi::c_void,
    ) -> BOOL;

    pub fn DetourUpdateProcessWithDll(
        hProcess: HANDLE,
        rlpDlls: *const windows_sys::core::PCSTR,
        nDlls: u32,
    ) -> BOOL;

    pub fn DetourCopyPayloadToProcess(
        hProcess: HANDLE,
        rguid: *const GUID,
        pvData: *const core::ffi::c_void,
        cbData: u32,
    ) -> BOOL;

    pub fn DetourFinishHelperProcess(a: HWND, b: HMODULE, c: windows_sys::core::PSTR, d: i32);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_process_is_false_in_test_binary() {
        // The test binary was not launched as a Detours helper, so this must
        // be FALSE (0). Proves the static lib linked and the calling
        // convention is correct.
        let r = unsafe { DetourIsHelperProcess() };
        assert_eq!(r, 0);
    }
}
