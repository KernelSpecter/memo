//! File signatures via Windows APIs: type, size, write time, change time, and
//! file id. Used to key the stat cache and to detect external modification.

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FType {
    File,
    Dir,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileSig {
    pub ftype: FType,
    pub size: u64,
    /// FILETIME (100ns ticks since 1601) of last write.
    pub mtime: i64,
    /// FILETIME of last metadata/content change (NTFS ChangeTime).
    pub change_time: i64,
    /// 64-bit file index (unique within a volume).
    pub file_id: u64,
}

#[cfg(windows)]
mod imp {
    use super::*;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FileBasicInfo, GetFileInformationByHandle, GetFileInformationByHandleEx,
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_BASIC_INFO,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE,
    };

    pub fn signature(path: &Path) -> Option<FileSig> {
        // Open via std so we don't juggle CreateFileW directly.
        // FILE_FLAG_BACKUP_SEMANTICS lets us open directories too; full share
        // mode so we never block the traced process.
        // Request only FILE_READ_ATTRIBUTES, not read access: we just need the
        // file's metadata, and this succeeds even when another process holds the
        // content open exclusively — so a locked-but-present file is not mistaken
        // for absent.
        let file = std::fs::OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)
            .ok()?;
        let handle = file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;

        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
            return None;
        }

        let mut basic: FILE_BASIC_INFO = unsafe { std::mem::zeroed() };
        let ok2 = unsafe {
            GetFileInformationByHandleEx(
                handle,
                FileBasicInfo,
                &mut basic as *mut _ as *mut core::ffi::c_void,
                core::mem::size_of::<FILE_BASIC_INFO>() as u32,
            )
        };

        let is_dir = info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
        let size = ((info.nFileSizeHigh as u64) << 32) | info.nFileSizeLow as u64;
        let mtime = filetime_to_i64(
            info.ftLastWriteTime.dwHighDateTime,
            info.ftLastWriteTime.dwLowDateTime,
        );
        let file_id = ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64;
        let change_time = if ok2 != 0 { basic.ChangeTime } else { mtime };

        Some(FileSig {
            ftype: if is_dir { FType::Dir } else { FType::File },
            size,
            mtime,
            change_time,
            file_id,
        })
    }

    fn filetime_to_i64(high: u32, low: u32) -> i64 {
        (((high as u64) << 32) | low as u64) as i64
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    pub fn signature(_path: &Path) -> Option<FileSig> {
        None
    }
}

/// Return the file signature, or `None` if the path does not exist / cannot be
/// opened for metadata.
pub fn file_signature(path: &Path) -> Option<FileSig> {
    imp::signature(path)
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn signature_of_file_reports_size_and_type() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f.txt");
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(b"hello").unwrap();
        f.sync_all().unwrap();
        drop(f);

        let sig = file_signature(&p).expect("sig");
        assert_eq!(sig.ftype, FType::File);
        assert_eq!(sig.size, 5);
        assert!(sig.file_id != 0);
    }

    #[test]
    fn signature_of_dir_reports_dir() {
        let dir = tempfile::tempdir().unwrap();
        let sig = file_signature(dir.path()).expect("sig");
        assert_eq!(sig.ftype, FType::Dir);
    }

    #[test]
    fn signature_of_absent_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("nope");
        assert!(file_signature(&p).is_none());
    }
}
