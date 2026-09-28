//! Direct NT-syscall FFI for test-only probe ops. Rust std doesn't route
//! through NtQueryInformationByName, the pre-Win8 NtQueryDirectoryFile, or
//! NtDeleteFile on this toolchain, so these ops let the integration tests prove
//! memo's hooks for those functions actually fire.
#![allow(non_snake_case, non_camel_case_types, clippy::upper_case_acronyms)]

use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FindClose, FindFirstFileW, GetFullPathNameW, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_LIST_DIRECTORY, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    WIN32_FIND_DATAW,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

type NTSTATUS = i32;

const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
const FILE_STAT_INFORMATION: i32 = 68;
const FILE_DIRECTORY_INFORMATION: i32 = 1;

#[repr(C)]
struct UNICODE_STRING {
    Length: u16,
    MaximumLength: u16,
    Buffer: *mut u16,
}

#[repr(C)]
struct OBJECT_ATTRIBUTES {
    Length: u32,
    RootDirectory: HANDLE,
    ObjectName: *mut UNICODE_STRING,
    Attributes: u32,
    SecurityDescriptor: *mut c_void,
    SecurityQualityOfService: *mut c_void,
}

#[repr(C)]
struct IO_STATUS_BLOCK {
    StatusOrPointer: usize,
    Information: usize,
}

unsafe fn ntdll_proc(name: &str) -> *mut c_void {
    let dll: Vec<u16> = "ntdll.dll"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let h = GetModuleHandleW(dll.as_ptr());
    if h.is_null() {
        return null_mut();
    }
    let cname: Vec<u8> = name.bytes().chain(std::iter::once(0)).collect();
    match GetProcAddress(h, cname.as_ptr()) {
        Some(f) => f as *mut c_void,
        None => null_mut(),
    }
}

fn wide0(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// UTF-16 of the NT path form of a Win32 path (no trailing NUL). The path is
/// first fully normalized (GetFullPathNameW collapses `.`/`..` and makes it
/// absolute) because the NT object manager, unlike the Win32 layer, does not
/// resolve `..` — a `\??\C:\a\..\b` passed straight through would fail to open.
fn nt_path(win32: &str) -> Vec<u16> {
    let full = full_path(win32);
    format!(r"\??\{}", full).encode_utf16().collect()
}

fn full_path(win32: &str) -> String {
    unsafe {
        let inp = wide0(win32);
        let need = GetFullPathNameW(inp.as_ptr(), 0, null_mut(), null_mut());
        if need == 0 {
            return win32.to_string();
        }
        let mut buf = vec![0u16; need as usize];
        let n = GetFullPathNameW(inp.as_ptr(), need, buf.as_mut_ptr(), null_mut());
        if n == 0 || n >= need {
            return win32.to_string();
        }
        String::from_utf16_lossy(&buf[..n as usize])
    }
}

/// Existence/stat check via NtQueryInformationByName (path-based, no handle).
/// Prints `QBYNAME <path> exists=<bool>`.
pub fn query_by_name(win32: &str) {
    unsafe {
        let f = ntdll_proc("NtQueryInformationByName");
        if f.is_null() {
            println!("QBYNAME {} unavailable", win32);
            return;
        }
        type F = unsafe extern "system" fn(
            *mut OBJECT_ATTRIBUTES,
            *mut IO_STATUS_BLOCK,
            *mut c_void,
            u32,
            i32,
        ) -> NTSTATUS;
        let func: F = std::mem::transmute(f);

        let mut nt = nt_path(win32);
        let mut us = UNICODE_STRING {
            Length: (nt.len() * 2) as u16,
            MaximumLength: (nt.len() * 2) as u16,
            Buffer: nt.as_mut_ptr(),
        };
        let mut oa = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: null_mut(),
            ObjectName: &mut us,
            Attributes: OBJ_CASE_INSENSITIVE,
            SecurityDescriptor: null_mut(),
            SecurityQualityOfService: null_mut(),
        };
        let mut iosb: IO_STATUS_BLOCK = zeroed();
        let mut buf = [0u8; 128];
        let st = func(
            &mut oa,
            &mut iosb,
            buf.as_mut_ptr() as *mut c_void,
            buf.len() as u32,
            FILE_STAT_INFORMATION,
        );
        println!("QBYNAME {} exists={}", win32, st >= 0);
    }
}

/// Enumerate a directory via the pre-Win8 NtQueryDirectoryFile.
/// Prints `QDIRFILE <dir> status=<hex>`.
pub fn query_dir_file(dir: &str) {
    unsafe {
        let name = wide0(dir);
        let h = CreateFileW(
            name.as_ptr(),
            GENERIC_READ | FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            null_mut(),
        );
        if h == INVALID_HANDLE_VALUE || h.is_null() {
            println!("QDIRFILE {} open_failed", dir);
            return;
        }
        let f = ntdll_proc("NtQueryDirectoryFile");
        if f.is_null() {
            println!("QDIRFILE {} unavailable", dir);
            CloseHandle(h);
            return;
        }
        #[allow(clippy::type_complexity)]
        type F = unsafe extern "system" fn(
            HANDLE,
            HANDLE,
            *mut c_void,
            *mut c_void,
            *mut IO_STATUS_BLOCK,
            *mut c_void,
            u32,
            i32,
            u8,
            *mut UNICODE_STRING,
            u8,
        ) -> NTSTATUS;
        let func: F = std::mem::transmute(f);
        let mut iosb: IO_STATUS_BLOCK = zeroed();
        let mut buf = [0u8; 4096];
        let st = func(
            h,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut iosb,
            buf.as_mut_ptr() as *mut c_void,
            buf.len() as u32,
            FILE_DIRECTORY_INFORMATION,
            0,
            null_mut(),
            0,
        );
        println!("QDIRFILE {} status={:#x}", dir, st);
        CloseHandle(h);
    }
}

/// Delete a file via NtDeleteFile (delete-by-name, no handle).
/// Prints `NTDELETE <path> status=<hex>`.
pub fn nt_delete(win32: &str) {
    unsafe {
        let f = ntdll_proc("NtDeleteFile");
        if f.is_null() {
            println!("NTDELETE {} unavailable", win32);
            return;
        }
        type F = unsafe extern "system" fn(*mut OBJECT_ATTRIBUTES) -> NTSTATUS;
        let func: F = std::mem::transmute(f);
        let mut nt = nt_path(win32);
        let mut us = UNICODE_STRING {
            Length: (nt.len() * 2) as u16,
            MaximumLength: (nt.len() * 2) as u16,
            Buffer: nt.as_mut_ptr(),
        };
        let mut oa = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: null_mut(),
            ObjectName: &mut us,
            Attributes: OBJ_CASE_INSENSITIVE,
            SecurityDescriptor: null_mut(),
            SecurityQualityOfService: null_mut(),
        };
        let st = func(&mut oa);
        println!("NTDELETE {} status={:#x}", win32, st);
    }
}

/// Look up one exact name via FindFirstFileW, which issues a single-name
/// NtQueryDirectoryFile filter on the parent directory (the I7 scenario).
/// Prints `FINDFIRST <path> found=<bool>`.
pub fn find_first(path: &str) {
    unsafe {
        let w = wide0(path);
        let mut data: WIN32_FIND_DATAW = zeroed();
        let h = FindFirstFileW(w.as_ptr(), &mut data);
        if h == INVALID_HANDLE_VALUE || h.is_null() {
            println!("FINDFIRST {} found=false", path);
        } else {
            println!("FINDFIRST {} found=true", path);
            FindClose(h);
        }
    }
}
