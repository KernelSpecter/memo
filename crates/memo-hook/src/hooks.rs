//! Detour installation and hook callbacks for NT file APIs.
//!
//! Each hook: bail to the real function if we're already inside a hook on this
//! thread (reentrancy), classify the path, snapshot before mutations, call the
//! real function, then report the observation. Hook logic is wrapped in
//! `catch_unwind`; the real function is always called with the original args.

use crate::client;
use crate::ntdef::*;
use crate::pathres::{classify_object, handle_to_win32};
use core::ffi::c_void;
use core::panic::AssertUnwindSafe;
use memo_core::paths::Classified;
use memo_proto::{AccessKind, MutateKind, TaintReason};
use std::panic::catch_unwind;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

// Real (trampoline) function pointers, filled by DetourAttach at install().
static mut REAL_NTCREATEFILE: *mut c_void = std::ptr::null_mut();
static mut REAL_NTOPENFILE: *mut c_void = std::ptr::null_mut();
static mut REAL_NTQUERYATTRIBUTESFILE: *mut c_void = std::ptr::null_mut();
static mut REAL_NTQUERYFULLATTRIBUTESFILE: *mut c_void = std::ptr::null_mut();
static mut REAL_NTSETINFORMATIONFILE: *mut c_void = std::ptr::null_mut();
static mut REAL_NTDEVICEIOCONTROLFILE: *mut c_void = std::ptr::null_mut();
static mut REAL_NTFSCONTROLFILE: *mut c_void = std::ptr::null_mut();
static mut REAL_NTQUERYDIRECTORYFILEEX: *mut c_void = std::ptr::null_mut();
static mut REAL_NTQUERYDIRECTORYFILE: *mut c_void = std::ptr::null_mut();
static mut REAL_NTQUERYINFORMATIONBYNAME: *mut c_void = std::ptr::null_mut();
static mut REAL_NTDELETEFILE: *mut c_void = std::ptr::null_mut();

fn is_not_found(status: NTSTATUS) -> bool {
    status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND
}

fn disposition_mutates(disp: u32) -> bool {
    matches!(
        disp,
        FILE_SUPERSEDE | FILE_CREATE | FILE_OPEN_IF | FILE_OVERWRITE | FILE_OVERWRITE_IF
    )
}

/// Classify + (for mutations) snapshot before the real open. Returns the
/// resolved file path (if a real filesystem file) and whether it's a mutation.
unsafe fn pre_open(
    oa: *mut OBJECT_ATTRIBUTES,
    desired: u32,
    disposition: u32,
    options: u32,
) -> (Option<String>, bool, bool) {
    let classified = classify_object(oa);
    let path = match classified {
        Some(Classified::File(p)) => Some(p),
        Some(Classified::Unknown(p)) => {
            // A path we can't map to a stable Win32 path: don't track it as a
            // file, but taint so the run isn't cached from an unobserved input.
            client::taint(
                TaintReason::InternalError,
                &format!("unmappable path {}", p),
            );
            None
        }
        _ => None,
    };
    let by_id = options & FILE_OPEN_BY_FILE_ID != 0;
    let is_mut = path.is_some()
        && (desired & WRITE_ACCESS_MASK != 0
            || disposition_mutates(disposition)
            || options & FILE_DELETE_ON_CLOSE != 0);

    if let Some(p) = &path {
        if by_id {
            client::taint(TaintReason::OpenById, p);
        } else if is_mut {
            client::premutate_wait(p.clone());
        }
    }
    (path, is_mut, by_id)
}

/// Report the observation after a real open, based on status and access.
fn post_open(
    path: Option<String>,
    is_mut: bool,
    by_id: bool,
    desired: u32,
    disposition: u32,
    status: NTSTATUS,
) {
    let path = match path {
        Some(p) => p,
        None => return,
    };
    if by_id {
        return;
    }
    if is_mut {
        // Only an open that succeeded (NT_SUCCESS) can have changed anything.
        if status >= 0 {
            let is_delete = desired & DELETE != 0;
            let kind = if is_delete {
                MutateKind::Delete
            } else if disposition == FILE_CREATE {
                // Exclusive create: fails if the target exists → pin absence.
                MutateKind::Create
            } else if disposition == FILE_OPEN || disposition == FILE_OVERWRITE {
                // Fail if the target is absent → the open succeeding pins that it
                // existed. (Content is pinned only if the tree also read it.)
                MutateKind::Write
            } else {
                // FILE_SUPERSEDE / FILE_OPEN_IF / FILE_OVERWRITE_IF: succeed whether
                // or not the target existed, and the output is restored from cache,
                // so pin nothing about the target unless the tree read it. This is
                // the path std's File::create takes (OPEN_IF + separate truncate).
                MutateKind::Truncate
            };
            // A write whose result can depend on the pre-run content — a
            // read-write handle, or an append (which preserves the prefix) — is
            // also reported as a Read so finalize pins the pre-run content. A
            // truncating write or a delete does not read prior content.
            if !is_delete && desired & (READ_ACCESS_MASK | FILE_APPEND_DATA) != 0 {
                client::access(AccessKind::Read, path.clone());
            }
            client::mutate(kind, path, None);
        }
        return;
    }
    if status == STATUS_SUCCESS {
        if desired & READ_ACCESS_MASK != 0 {
            client::access(AccessKind::Read, path);
        } else {
            client::access(AccessKind::Probe, path);
        }
    } else if is_not_found(status) {
        client::access(AccessKind::ProbeAbsent, path);
    } else {
        // Other errors (access denied, sharing violation): the path was probed.
        client::access(AccessKind::Probe, path);
    }
}

// ---- NtCreateFile ----

#[allow(clippy::too_many_arguments)]
unsafe extern "system" fn h_ntcreatefile(
    file_handle: *mut HANDLE,
    desired: u32,
    oa: *mut OBJECT_ATTRIBUTES,
    iosb: *mut IO_STATUS_BLOCK,
    alloc: *mut i64,
    attrs: u32,
    share: u32,
    disposition: u32,
    options: u32,
    ea: *mut c_void,
    ealen: u32,
) -> NTSTATUS {
    let real: NtCreateFileFn = core::mem::transmute(REAL_NTCREATEFILE);
    let guard = client::enter();
    if guard.is_none() {
        return real(
            file_handle,
            desired,
            oa,
            iosb,
            alloc,
            attrs,
            share,
            disposition,
            options,
            ea,
            ealen,
        );
    }
    let pre = catch_unwind(AssertUnwindSafe(|| {
        pre_open(oa, desired, disposition, options)
    }))
    .unwrap_or((None, false, false));
    let status = real(
        file_handle,
        desired,
        oa,
        iosb,
        alloc,
        attrs,
        share,
        disposition,
        options,
        ea,
        ealen,
    );
    let _ = catch_unwind(AssertUnwindSafe(|| {
        post_open(pre.0, pre.1, pre.2, desired, disposition, status)
    }));
    status
}

// ---- NtOpenFile ----

unsafe extern "system" fn h_ntopenfile(
    file_handle: *mut HANDLE,
    desired: u32,
    oa: *mut OBJECT_ATTRIBUTES,
    iosb: *mut IO_STATUS_BLOCK,
    share: u32,
    options: u32,
) -> NTSTATUS {
    let real: NtOpenFileFn = core::mem::transmute(REAL_NTOPENFILE);
    let guard = client::enter();
    if guard.is_none() {
        return real(file_handle, desired, oa, iosb, share, options);
    }
    // NtOpenFile never creates; disposition is effectively FILE_OPEN.
    let pre = catch_unwind(AssertUnwindSafe(|| {
        pre_open(oa, desired, FILE_OPEN, options)
    }))
    .unwrap_or((None, false, false));
    let status = real(file_handle, desired, oa, iosb, share, options);
    let _ = catch_unwind(AssertUnwindSafe(|| {
        post_open(pre.0, pre.1, pre.2, desired, FILE_OPEN, status)
    }));
    status
}

// ---- NtQueryAttributesFile / NtQueryFullAttributesFile (path-based stat) ----

unsafe fn query_attrs_common(oa: *mut OBJECT_ATTRIBUTES, status: NTSTATUS) {
    match classify_object(oa) {
        Some(Classified::File(p)) => {
            if is_not_found(status) {
                client::access(AccessKind::ProbeAbsent, p);
            } else {
                client::access(AccessKind::Probe, p);
            }
        }
        Some(Classified::Unknown(p)) => {
            client::taint(
                TaintReason::InternalError,
                &format!("unmappable path {}", p),
            );
        }
        _ => {}
    }
}

unsafe extern "system" fn h_ntqueryattributesfile(
    oa: *mut OBJECT_ATTRIBUTES,
    info: *mut c_void,
) -> NTSTATUS {
    let real: NtQueryAttributesFileFn = core::mem::transmute(REAL_NTQUERYATTRIBUTESFILE);
    let guard = client::enter();
    if guard.is_none() {
        return real(oa, info);
    }
    let status = real(oa, info);
    let _ = catch_unwind(AssertUnwindSafe(|| query_attrs_common(oa, status)));
    status
}

unsafe extern "system" fn h_ntqueryfullattributesfile(
    oa: *mut OBJECT_ATTRIBUTES,
    info: *mut c_void,
) -> NTSTATUS {
    let real: NtQueryAttributesFileFn = core::mem::transmute(REAL_NTQUERYFULLATTRIBUTESFILE);
    let guard = client::enter();
    if guard.is_none() {
        return real(oa, info);
    }
    let status = real(oa, info);
    let _ = catch_unwind(AssertUnwindSafe(|| query_attrs_common(oa, status)));
    status
}

// ---- NtSetInformationFile (rename, delete disposition, set metadata) ----

unsafe fn set_info_pre(
    file_handle: HANDLE,
    info: *mut c_void,
    length: u32,
    class: i32,
) -> Option<(MutateKind, String, Option<String>)> {
    // Check the information class BEFORE resolving the handle to a path: only
    // these classes mutate, and GetFinalPathNameByHandleW is expensive. Skipping
    // it for the others (notably FilePositionInformation, issued by every seek)
    // keeps seek-heavy workloads fast.
    if !matches!(
        class,
        FILE_DISPOSITION_INFORMATION
            | FILE_DISPOSITION_INFORMATION_EX
            | FILE_RENAME_INFORMATION
            | FILE_LINK_INFORMATION
            | FILE_BASIC_INFORMATION
            | FILE_END_OF_FILE_INFORMATION
    ) {
        return None;
    }
    let path = handle_to_win32(file_handle)?;
    match class {
        FILE_DISPOSITION_INFORMATION | FILE_DISPOSITION_INFORMATION_EX => {
            // First byte is the delete flag (Disposition on EX has DELETE=1 bit).
            let del = if length >= 1 {
                (*(info as *const u8)) & 1 != 0
            } else {
                false
            };
            if del {
                client::premutate_wait(path.clone());
                Some((MutateKind::Delete, path, None))
            } else {
                None
            }
        }
        FILE_RENAME_INFORMATION | FILE_LINK_INFORMATION => {
            let ri = &*(info as *const FILE_RENAME_INFORMATION);
            let name_len = (ri.FileNameLength / 2) as usize;
            let target = if name_len > 0 {
                let name_ptr = std::ptr::addr_of!(ri.FileName) as *const u16;
                let slice = std::slice::from_raw_parts(name_ptr, name_len);
                let raw = String::from_utf16_lossy(slice);
                if !ri.RootDirectory.is_null() {
                    handle_to_win32(ri.RootDirectory)
                        .map(|base| format!("{}\\{}", base.trim_end_matches('\\'), raw))
                } else {
                    // Absolute NT path; normalize via classifier.
                    classify_target(&raw)
                }
            } else {
                None
            };
            client::premutate_wait(path.clone());
            if let Some(t) = &target {
                client::premutate_wait(t.clone());
            }
            let kind = if class == FILE_RENAME_INFORMATION {
                MutateKind::Rename
            } else {
                MutateKind::Create
            };
            Some((kind, path, target))
        }
        FILE_BASIC_INFORMATION | FILE_END_OF_FILE_INFORMATION => {
            client::premutate_wait(path.clone());
            Some((MutateKind::SetMeta, path, None))
        }
        _ => None,
    }
}

fn classify_target(raw: &str) -> Option<String> {
    // `raw` from a rename target is an NT path or a bare relative name; reuse
    // the volume-aware classifier via a fake object is overkill — normalize.
    use memo_core::paths::{from_nt, VolumeMap};
    match from_nt(raw, &VolumeMap::from_system()) {
        Classified::File(p) => Some(p),
        Classified::Device | Classified::Unknown(_) => None,
    }
}

unsafe extern "system" fn h_ntsetinformationfile(
    file_handle: HANDLE,
    iosb: *mut IO_STATUS_BLOCK,
    info: *mut c_void,
    length: u32,
    class: i32,
) -> NTSTATUS {
    let real: NtSetInformationFileFn = core::mem::transmute(REAL_NTSETINFORMATIONFILE);
    let guard = client::enter();
    if guard.is_none() {
        return real(file_handle, iosb, info, length, class);
    }
    let pending = catch_unwind(AssertUnwindSafe(|| {
        set_info_pre(file_handle, info, length, class)
    }))
    .unwrap_or(None);
    let status = real(file_handle, iosb, info, length, class);
    if status == STATUS_SUCCESS {
        if let Some((kind, path, target)) = pending {
            let _ = catch_unwind(AssertUnwindSafe(|| client::mutate(kind, path, target)));
        }
    }
    status
}

// ---- NtDeviceIoControlFile (network taint) ----

#[allow(clippy::too_many_arguments)]
unsafe extern "system" fn h_ntdeviceiocontrolfile(
    file_handle: HANDLE,
    event: HANDLE,
    apc: *mut c_void,
    apc_ctx: *mut c_void,
    iosb: *mut IO_STATUS_BLOCK,
    ioctl: u32,
    in_buf: *mut c_void,
    in_len: u32,
    out_buf: *mut c_void,
    out_len: u32,
) -> NTSTATUS {
    let real: NtDeviceIoControlFileFn = core::mem::transmute(REAL_NTDEVICEIOCONTROLFILE);
    let guard = client::enter();
    if guard.is_none() {
        return real(
            file_handle,
            event,
            apc,
            apc_ctx,
            iosb,
            ioctl,
            in_buf,
            in_len,
            out_buf,
            out_len,
        );
    }
    if matches!(
        ioctl,
        IOCTL_AFD_CONNECT | IOCTL_AFD_SUPER_CONNECT | IOCTL_AFD_SEND | IOCTL_AFD_SEND_DATAGRAM
    ) {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            client::taint(TaintReason::Network, "AFD connect/send")
        }));
    }
    real(
        file_handle,
        event,
        apc,
        apc_ctx,
        iosb,
        ioctl,
        in_buf,
        in_len,
        out_buf,
        out_len,
    )
}

// ---- NtFsControlFile (reparse point taint) ----

#[allow(clippy::too_many_arguments)]
unsafe extern "system" fn h_ntfscontrolfile(
    file_handle: HANDLE,
    event: HANDLE,
    apc: *mut c_void,
    apc_ctx: *mut c_void,
    iosb: *mut IO_STATUS_BLOCK,
    ioctl: u32,
    in_buf: *mut c_void,
    in_len: u32,
    out_buf: *mut c_void,
    out_len: u32,
) -> NTSTATUS {
    let real: NtFsControlFileFn = core::mem::transmute(REAL_NTFSCONTROLFILE);
    let guard = client::enter();
    if guard.is_none() {
        return real(
            file_handle,
            event,
            apc,
            apc_ctx,
            iosb,
            ioctl,
            in_buf,
            in_len,
            out_buf,
            out_len,
        );
    }
    if matches!(ioctl, FSCTL_SET_REPARSE_POINT | FSCTL_DELETE_REPARSE_POINT) {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            client::taint(TaintReason::ReparsePoint, "reparse point set/delete")
        }));
    }
    real(
        file_handle,
        event,
        apc,
        apc_ctx,
        iosb,
        ioctl,
        in_buf,
        in_len,
        out_buf,
        out_len,
    )
}

/// Classify a directory-query result. A query carrying a specific (non-wildcard)
/// `FileName` filter is a single-name lookup — `FindFirstFile("dir\\exact")`,
/// `GetLongPathName`, stat-by-enumeration — not an enumeration of the whole
/// directory, so it is reported as a Probe of `dir\name`. Only a query with no
/// filter or a wildcard (`*`/`?`) fingerprints the directory as a List.
unsafe fn on_dir_query(file_handle: HANDLE, file_name: *mut UNICODE_STRING, status: NTSTATUS) {
    let filter = if !file_name.is_null() {
        let us = &*file_name;
        if !us.Buffer.is_null() && us.Length > 0 {
            let len = (us.Length / 2) as usize;
            Some(String::from_utf16_lossy(std::slice::from_raw_parts(
                us.Buffer, len,
            )))
        } else {
            None
        }
    } else {
        None
    };
    let dir = match handle_to_win32(file_handle) {
        Some(d) => d,
        None => return,
    };
    match filter {
        Some(name) if !name.is_empty() && !name.contains('*') && !name.contains('?') => {
            let path = format!("{}\\{}", dir.trim_end_matches('\\'), name);
            let absent = matches!(
                status,
                STATUS_NO_SUCH_FILE
                    | STATUS_NO_MORE_FILES
                    | STATUS_OBJECT_NAME_NOT_FOUND
                    | STATUS_OBJECT_PATH_NOT_FOUND
            );
            if absent {
                client::access(AccessKind::ProbeAbsent, path);
            } else {
                client::access(AccessKind::Probe, path);
            }
        }
        // A real enumeration: snapshot the directory synchronously (PreList) so
        // memo records what the command is about to see, before the tree writes
        // into the directory itself. Deduped by memo (a repeat PreList for a dir
        // already snapshotted just re-acks).
        _ => client::prelist_wait(dir),
    }
}

// ---- NtQueryDirectoryFileEx (directory listing) ----

#[allow(clippy::too_many_arguments)]
unsafe extern "system" fn h_ntquerydirectoryfileex(
    file_handle: HANDLE,
    event: HANDLE,
    apc: *mut c_void,
    apc_ctx: *mut c_void,
    iosb: *mut IO_STATUS_BLOCK,
    info: *mut c_void,
    length: u32,
    class: i32,
    flags: u32,
    file_name: *mut UNICODE_STRING,
) -> NTSTATUS {
    let real: NtQueryDirectoryFileExFn = core::mem::transmute(REAL_NTQUERYDIRECTORYFILEEX);
    let guard = client::enter();
    if guard.is_none() {
        return real(
            file_handle,
            event,
            apc,
            apc_ctx,
            iosb,
            info,
            length,
            class,
            flags,
            file_name,
        );
    }
    let status = real(
        file_handle,
        event,
        apc,
        apc_ctx,
        iosb,
        info,
        length,
        class,
        flags,
        file_name,
    );
    let _ = catch_unwind(AssertUnwindSafe(|| {
        on_dir_query(file_handle, file_name, status)
    }));
    status
}

// ---- NtQueryDirectoryFile (pre-Win8 directory enumeration) ----

#[allow(clippy::too_many_arguments)]
unsafe extern "system" fn h_ntquerydirectoryfile(
    file_handle: HANDLE,
    event: HANDLE,
    apc: *mut c_void,
    apc_ctx: *mut c_void,
    iosb: *mut IO_STATUS_BLOCK,
    info: *mut c_void,
    length: u32,
    class: i32,
    return_single_entry: u8,
    file_name: *mut UNICODE_STRING,
    restart_scan: u8,
) -> NTSTATUS {
    let real: NtQueryDirectoryFileFn = core::mem::transmute(REAL_NTQUERYDIRECTORYFILE);
    let guard = client::enter();
    if guard.is_none() {
        return real(
            file_handle,
            event,
            apc,
            apc_ctx,
            iosb,
            info,
            length,
            class,
            return_single_entry,
            file_name,
            restart_scan,
        );
    }
    let status = real(
        file_handle,
        event,
        apc,
        apc_ctx,
        iosb,
        info,
        length,
        class,
        return_single_entry,
        file_name,
        restart_scan,
    );
    let _ = catch_unwind(AssertUnwindSafe(|| {
        on_dir_query(file_handle, file_name, status)
    }));
    status
}

// ---- NtQueryInformationByName (newer path-based stat) ----

unsafe extern "system" fn h_ntqueryinformationbyname(
    oa: *mut OBJECT_ATTRIBUTES,
    iosb: *mut IO_STATUS_BLOCK,
    info: *mut c_void,
    length: u32,
    class: i32,
) -> NTSTATUS {
    let real: NtQueryInformationByNameFn = core::mem::transmute(REAL_NTQUERYINFORMATIONBYNAME);
    let guard = client::enter();
    if guard.is_none() {
        return real(oa, iosb, info, length, class);
    }
    let status = real(oa, iosb, info, length, class);
    let _ = catch_unwind(AssertUnwindSafe(|| query_attrs_common(oa, status)));
    status
}

// ---- NtDeleteFile (delete by name) ----

unsafe extern "system" fn h_ntdeletefile(oa: *mut OBJECT_ATTRIBUTES) -> NTSTATUS {
    let real: NtDeleteFileFn = core::mem::transmute(REAL_NTDELETEFILE);
    let guard = client::enter();
    if guard.is_none() {
        return real(oa);
    }
    let path = catch_unwind(AssertUnwindSafe(|| match classify_object(oa) {
        Some(Classified::File(p)) => Some(p),
        Some(Classified::Unknown(p)) => {
            client::taint(
                TaintReason::InternalError,
                &format!("unmappable path {}", p),
            );
            None
        }
        _ => None,
    }))
    .unwrap_or(None);
    if let Some(p) = &path {
        let _ = catch_unwind(AssertUnwindSafe(|| client::premutate_wait(p.clone())));
    }
    let status = real(oa);
    if status >= 0 {
        if let Some(p) = path {
            let _ = catch_unwind(AssertUnwindSafe(|| {
                client::mutate(MutateKind::Delete, p, None)
            }));
        }
    }
    status
}

/// NtQueryDirectoryFileEx signature (declared here since it has 10 args).
pub type NtQueryDirectoryFileExFn = unsafe extern "system" fn(
    HANDLE,
    HANDLE,
    *mut c_void,
    *mut c_void,
    *mut IO_STATUS_BLOCK,
    *mut c_void,
    u32,
    i32,
    u32,
    *mut UNICODE_STRING,
) -> NTSTATUS;

pub(crate) unsafe fn proc_addr(module: *mut c_void, name: &str) -> *mut c_void {
    let cname: Vec<u8> = name.bytes().chain(std::iter::once(0)).collect();
    match GetProcAddress(module as _, cname.as_ptr()) {
        Some(f) => f as *mut c_void,
        None => std::ptr::null_mut(),
    }
}

/// Install all file hooks in a single Detours transaction. On any failure,
/// report a HookInstallFailed taint (the run stays uncacheable) but never crash.
pub fn install() {
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe { install_inner() }));
}

unsafe fn install_inner() {
    use memo_detours::*;

    let ntdll_name: Vec<u16> = "ntdll.dll"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let ntdll = GetModuleHandleW(ntdll_name.as_ptr());
    if ntdll.is_null() {
        client::taint(TaintReason::HookInstallFailed, "no ntdll");
        return;
    }

    REAL_NTCREATEFILE = proc_addr(ntdll, "NtCreateFile");
    REAL_NTOPENFILE = proc_addr(ntdll, "NtOpenFile");
    REAL_NTQUERYATTRIBUTESFILE = proc_addr(ntdll, "NtQueryAttributesFile");
    REAL_NTQUERYFULLATTRIBUTESFILE = proc_addr(ntdll, "NtQueryFullAttributesFile");
    REAL_NTSETINFORMATIONFILE = proc_addr(ntdll, "NtSetInformationFile");
    REAL_NTDEVICEIOCONTROLFILE = proc_addr(ntdll, "NtDeviceIoControlFile");
    REAL_NTFSCONTROLFILE = proc_addr(ntdll, "NtFsControlFile");
    REAL_NTQUERYDIRECTORYFILEEX = proc_addr(ntdll, "NtQueryDirectoryFileEx");
    REAL_NTQUERYDIRECTORYFILE = proc_addr(ntdll, "NtQueryDirectoryFile");
    REAL_NTQUERYINFORMATIONBYNAME = proc_addr(ntdll, "NtQueryInformationByName");
    REAL_NTDELETEFILE = proc_addr(ntdll, "NtDeleteFile");

    if DetourTransactionBegin() != 0 {
        client::taint(TaintReason::HookInstallFailed, "txn begin");
        return;
    }
    DetourUpdateThread(windows_sys::Win32::System::Threading::GetCurrentThread());

    attach(
        std::ptr::addr_of_mut!(REAL_NTCREATEFILE),
        h_ntcreatefile as *const () as *mut c_void,
    );
    attach(
        std::ptr::addr_of_mut!(REAL_NTOPENFILE),
        h_ntopenfile as *const () as *mut c_void,
    );
    attach(
        std::ptr::addr_of_mut!(REAL_NTQUERYATTRIBUTESFILE),
        h_ntqueryattributesfile as *const () as *mut c_void,
    );
    attach(
        std::ptr::addr_of_mut!(REAL_NTQUERYFULLATTRIBUTESFILE),
        h_ntqueryfullattributesfile as *const () as *mut c_void,
    );
    attach(
        std::ptr::addr_of_mut!(REAL_NTSETINFORMATIONFILE),
        h_ntsetinformationfile as *const () as *mut c_void,
    );
    attach(
        std::ptr::addr_of_mut!(REAL_NTDEVICEIOCONTROLFILE),
        h_ntdeviceiocontrolfile as *const () as *mut c_void,
    );
    attach(
        std::ptr::addr_of_mut!(REAL_NTFSCONTROLFILE),
        h_ntfscontrolfile as *const () as *mut c_void,
    );
    attach(
        std::ptr::addr_of_mut!(REAL_NTQUERYDIRECTORYFILEEX),
        h_ntquerydirectoryfileex as *const () as *mut c_void,
    );
    attach(
        std::ptr::addr_of_mut!(REAL_NTQUERYDIRECTORYFILE),
        h_ntquerydirectoryfile as *const () as *mut c_void,
    );
    // NtQueryInformationByName is absent on older Windows; attach() no-ops on null.
    attach(
        std::ptr::addr_of_mut!(REAL_NTQUERYINFORMATIONBYNAME),
        h_ntqueryinformationbyname as *const () as *mut c_void,
    );
    attach(
        std::ptr::addr_of_mut!(REAL_NTDELETEFILE),
        h_ntdeletefile as *const () as *mut c_void,
    );

    // Child-process propagation hooks (Task 10).
    crate::childhook::attach_child_hooks();
    crate::ctrlhook::attach();

    if DetourTransactionCommit() != 0 {
        client::taint(TaintReason::HookInstallFailed, "txn commit");
        return;
    }
    crate::ctrlhook::register();
}

/// `real` points at the static holding the original function; Detours
/// rewrites it to the trampoline. Skipped if the export wasn't found.
unsafe fn attach(real: *mut *mut c_void, detour: *mut c_void) {
    if (*real).is_null() {
        return;
    }
    memo_detours::DetourAttach(real, detour);
}
