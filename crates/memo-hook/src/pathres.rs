//! Resolve NT `OBJECT_ATTRIBUTES` and handles to Win32 paths, classifying
//! non-filesystem devices out.
#![allow(dead_code)] // consumers land in Task 9 (hooks)

use crate::ntdef::OBJECT_ATTRIBUTES;
use memo_core::paths::{from_nt, Classified, VolumeMap};
use std::sync::OnceLock;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Storage::FileSystem::{
    GetFinalPathNameByHandleW, FILE_NAME_NORMALIZED, VOLUME_NAME_DOS,
};

static VOLUMES: OnceLock<VolumeMap> = OnceLock::new();

fn volumes() -> &'static VolumeMap {
    VOLUMES.get_or_init(VolumeMap::from_system)
}

/// Read the target path from OBJECT_ATTRIBUTES, resolving a RootDirectory
/// handle if present. Returns the classification (File or Device).
///
/// # Safety
/// `oa` must be a valid pointer for the duration of the call (it is, inside a
/// hook — it is the caller's argument).
pub unsafe fn classify_object(oa: *mut OBJECT_ATTRIBUTES) -> Option<Classified> {
    if oa.is_null() {
        return None;
    }
    let oa = &*oa;
    if oa.ObjectName.is_null() {
        return None;
    }
    let us = &*oa.ObjectName;
    if us.Buffer.is_null() || us.Length == 0 {
        return None;
    }
    let len = (us.Length / 2) as usize;
    let slice = std::slice::from_raw_parts(us.Buffer, len);
    let name = String::from_utf16_lossy(slice);

    if !oa.RootDirectory.is_null() {
        // Name is relative to a directory handle.
        match handle_to_win32(oa.RootDirectory) {
            Some(base) => {
                let joined = format!("{}\\{}", base.trim_end_matches('\\'), name);
                Some(from_nt(&joined, volumes()))
            }
            None => None,
        }
    } else {
        Some(from_nt(&name, volumes()))
    }
}

/// Resolve a directory/file handle to a Win32 path.
///
/// # Safety
/// `h` must be a valid, open handle.
pub unsafe fn handle_to_win32(h: HANDLE) -> Option<String> {
    let mut buf = vec![0u16; 1024];
    let mut n = GetFinalPathNameByHandleW(
        h,
        buf.as_mut_ptr(),
        buf.len() as u32,
        FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
    );
    if n == 0 {
        return None;
    }
    if n as usize > buf.len() {
        buf.resize(n as usize + 1, 0);
        n = GetFinalPathNameByHandleW(
            h,
            buf.as_mut_ptr(),
            buf.len() as u32,
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
        );
        if n == 0 {
            return None;
        }
    }
    let s = String::from_utf16_lossy(&buf[..n as usize]);
    Some(strip_verbatim(&s))
}

/// Strip a `\\?\` verbatim prefix; map `\\?\UNC\srv\sh` back to `\\srv\sh`.
fn strip_verbatim(s: &str) -> String {
    if let Some(rest) = s.strip_prefix("\\\\?\\") {
        if let Some(unc) = rest.strip_prefix("UNC\\") {
            return format!("\\\\{}", unc);
        }
        return rest.to_string();
    }
    s.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_verbatim_drive() {
        assert_eq!(strip_verbatim("\\\\?\\C:\\a\\b"), "C:\\a\\b");
    }

    #[test]
    fn strips_verbatim_unc() {
        assert_eq!(strip_verbatim("\\\\?\\UNC\\srv\\sh\\x"), "\\\\srv\\sh\\x");
    }

    #[test]
    fn passes_plain_path() {
        assert_eq!(strip_verbatim("C:\\already"), "C:\\already");
    }
}
