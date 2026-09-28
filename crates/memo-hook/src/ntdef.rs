//! NT-native structures and function-pointer types not exposed (or not exposed
//! conveniently) by windows-sys. Only what the hooks need.

#![allow(
    non_snake_case,
    non_camel_case_types,
    dead_code,
    clippy::upper_case_acronyms
)]

use core::ffi::c_void;
use windows_sys::Win32::Foundation::HANDLE;

pub type NTSTATUS = i32;

pub const STATUS_SUCCESS: NTSTATUS = 0;
pub const STATUS_OBJECT_NAME_NOT_FOUND: NTSTATUS = 0xC0000034u32 as i32;
pub const STATUS_OBJECT_PATH_NOT_FOUND: NTSTATUS = 0xC000003Au32 as i32;
/// A directory query with a single-name filter that matched nothing.
pub const STATUS_NO_SUCH_FILE: NTSTATUS = 0xC000000Fu32 as i32;
pub const STATUS_NO_MORE_FILES: NTSTATUS = 0x80000006u32 as i32;

#[repr(C)]
pub struct UNICODE_STRING {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: *mut u16,
}

#[repr(C)]
pub struct OBJECT_ATTRIBUTES {
    pub Length: u32,
    pub RootDirectory: HANDLE,
    pub ObjectName: *mut UNICODE_STRING,
    pub Attributes: u32,
    pub SecurityDescriptor: *mut c_void,
    pub SecurityQualityOfService: *mut c_void,
}

/// On x64 the first field is a pointer-sized union of {NTSTATUS, PVOID}. We
/// read the low 32 bits as the status.
#[repr(C)]
pub struct IO_STATUS_BLOCK {
    pub StatusOrPointer: usize,
    pub Information: usize,
}

impl IO_STATUS_BLOCK {
    pub fn status(&self) -> NTSTATUS {
        (self.StatusOrPointer as u32) as i32
    }
}

// OBJECT_ATTRIBUTES.Attributes flag: object name is a file id, not a path.
pub const OBJ_DONT_REPARSE: u32 = 0x00001000;
// CreateOptions / OpenOptions flags.
pub const FILE_OPEN_BY_FILE_ID: u32 = 0x00002000;
pub const FILE_DELETE_ON_CLOSE: u32 = 0x00001000;
pub const FILE_DIRECTORY_FILE: u32 = 0x00000001;

// CreateDisposition values.
pub const FILE_SUPERSEDE: u32 = 0x00000000;
pub const FILE_OPEN: u32 = 0x00000001;
pub const FILE_CREATE: u32 = 0x00000002;
pub const FILE_OPEN_IF: u32 = 0x00000003;
pub const FILE_OVERWRITE: u32 = 0x00000004;
pub const FILE_OVERWRITE_IF: u32 = 0x00000005;

// DesiredAccess bits relevant to read vs write classification.
pub const FILE_READ_DATA: u32 = 0x0001;
pub const FILE_WRITE_DATA: u32 = 0x0002;
pub const FILE_APPEND_DATA: u32 = 0x0004;
pub const FILE_READ_EA: u32 = 0x0008;
pub const FILE_WRITE_EA: u32 = 0x0010;
pub const FILE_EXECUTE: u32 = 0x0020;
pub const FILE_READ_ATTRIBUTES: u32 = 0x0080;
pub const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
pub const DELETE: u32 = 0x0001_0000;
pub const GENERIC_READ: u32 = 0x8000_0000;
pub const GENERIC_WRITE: u32 = 0x4000_0000;
pub const GENERIC_ALL: u32 = 0x1000_0000;
pub const GENERIC_EXECUTE: u32 = 0x2000_0000;

/// Any bit that implies the caller may modify the file's data or metadata.
pub const WRITE_ACCESS_MASK: u32 = FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_WRITE_EA
    | FILE_WRITE_ATTRIBUTES
    | DELETE
    | GENERIC_WRITE
    | GENERIC_ALL;

/// Any bit that implies the caller reads file content.
pub const READ_ACCESS_MASK: u32 =
    FILE_READ_DATA | FILE_EXECUTE | GENERIC_READ | GENERIC_ALL | GENERIC_EXECUTE;

// NtSetInformationFile classes we care about.
pub const FILE_RENAME_INFORMATION: i32 = 10;
pub const FILE_DISPOSITION_INFORMATION: i32 = 13;
pub const FILE_BASIC_INFORMATION: i32 = 4;
pub const FILE_END_OF_FILE_INFORMATION: i32 = 20;
pub const FILE_DISPOSITION_INFORMATION_EX: i32 = 64;
pub const FILE_LINK_INFORMATION: i32 = 11;

#[repr(C)]
pub struct FILE_DISPOSITION_INFORMATION {
    pub DeleteFile: u8,
}

#[repr(C)]
pub struct FILE_RENAME_INFORMATION {
    pub ReplaceIfExists: u8,
    pub RootDirectory: HANDLE,
    pub FileNameLength: u32,
    pub FileName: [u16; 1], // variable length
}

// FSCTL codes.
pub const FSCTL_SET_REPARSE_POINT: u32 = 0x000900A4;
pub const FSCTL_DELETE_REPARSE_POINT: u32 = 0x000900AC;

// AFD (socket) IOCTLs indicating real network activity. Codes are
// (0x12 << 12) | (op << 2) | method: CONNECT is op 1, SEND 7, SEND_DATAGRAM 8
// and SUPER_CONNECT (ConnectEx, which libuv uses for every TCP connect) 49.
// Not 0x1207B: that is op 30, AFD_GET_INFO, which every socket creation issues.
pub const IOCTL_AFD_CONNECT: u32 = 0x00012007;
pub const IOCTL_AFD_SUPER_CONNECT: u32 = 0x000120C7;
pub const IOCTL_AFD_SEND: u32 = 0x0001201F;
pub const IOCTL_AFD_SEND_DATAGRAM: u32 = 0x00012023;

// --- native function pointer signatures ---

pub type NtCreateFileFn = unsafe extern "system" fn(
    FileHandle: *mut HANDLE,
    DesiredAccess: u32,
    ObjectAttributes: *mut OBJECT_ATTRIBUTES,
    IoStatusBlock: *mut IO_STATUS_BLOCK,
    AllocationSize: *mut i64,
    FileAttributes: u32,
    ShareAccess: u32,
    CreateDisposition: u32,
    CreateOptions: u32,
    EaBuffer: *mut c_void,
    EaLength: u32,
) -> NTSTATUS;

pub type NtOpenFileFn = unsafe extern "system" fn(
    FileHandle: *mut HANDLE,
    DesiredAccess: u32,
    ObjectAttributes: *mut OBJECT_ATTRIBUTES,
    IoStatusBlock: *mut IO_STATUS_BLOCK,
    ShareAccess: u32,
    OpenOptions: u32,
) -> NTSTATUS;

pub type NtQueryAttributesFileFn = unsafe extern "system" fn(
    ObjectAttributes: *mut OBJECT_ATTRIBUTES,
    FileInformation: *mut c_void,
) -> NTSTATUS;

pub type NtSetInformationFileFn = unsafe extern "system" fn(
    FileHandle: HANDLE,
    IoStatusBlock: *mut IO_STATUS_BLOCK,
    FileInformation: *mut c_void,
    Length: u32,
    FileInformationClass: i32,
) -> NTSTATUS;

pub type NtDeviceIoControlFileFn = unsafe extern "system" fn(
    FileHandle: HANDLE,
    Event: HANDLE,
    ApcRoutine: *mut c_void,
    ApcContext: *mut c_void,
    IoStatusBlock: *mut IO_STATUS_BLOCK,
    IoControlCode: u32,
    InputBuffer: *mut c_void,
    InputBufferLength: u32,
    OutputBuffer: *mut c_void,
    OutputBufferLength: u32,
) -> NTSTATUS;

pub type NtFsControlFileFn = NtDeviceIoControlFileFn;

pub type NtDeleteFileFn =
    unsafe extern "system" fn(ObjectAttributes: *mut OBJECT_ATTRIBUTES) -> NTSTATUS;

/// Newer path-based stat (Rust std, Python 3.12+, Win11 GetFileInformationByName).
/// May be absent on older Windows — resolve defensively.
pub type NtQueryInformationByNameFn = unsafe extern "system" fn(
    ObjectAttributes: *mut OBJECT_ATTRIBUTES,
    IoStatusBlock: *mut IO_STATUS_BLOCK,
    FileInformation: *mut c_void,
    Length: u32,
    FileInformationClass: i32,
) -> NTSTATUS;

/// Directory enumeration (the pre-Win8 form; libuv/Node's readdir and .NET call
/// it directly). Same shape as the Ex form but with ReturnSingleEntry / FileName
/// filter / RestartScan instead of the Ex flags word.
pub type NtQueryDirectoryFileFn = unsafe extern "system" fn(
    FileHandle: HANDLE,
    Event: HANDLE,
    ApcRoutine: *mut c_void,
    ApcContext: *mut c_void,
    IoStatusBlock: *mut IO_STATUS_BLOCK,
    FileInformation: *mut c_void,
    Length: u32,
    FileInformationClass: i32,
    ReturnSingleEntry: u8,
    FileName: *mut UNICODE_STRING,
    RestartScan: u8,
) -> NTSTATUS;
