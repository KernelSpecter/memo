//! Launch the target process under a job object with our hook DLL injected,
//! capture its stdout/stderr, and wait for the whole process tree to finish.

use anyhow::{anyhow, Result};
use memo_proto::RunPayload;
use serde::{Deserialize, Serialize};
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::path::Path;
use std::sync::{Arc, Mutex};
use windows_sys::Win32::Foundation::{
    CloseHandle, SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, SetInformationJobObject, TerminateJobObject,
    JobObjectAssociateCompletionPortInformation, JOBOBJECT_ASSOCIATE_COMPLETION_PORT,
};
use windows_sys::Win32::System::SystemServices::{
    JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO, JOB_OBJECT_MSG_NEW_PROCESS,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::IO::{CreateIoCompletionPort, GetQueuedCompletionStatus};
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, ResumeThread, WaitForSingleObject, CREATE_SUSPENDED,
    CREATE_UNICODE_ENVIRONMENT, INFINITE, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Stream {
    Out,
    Err,
}

/// One chunk of captured console output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chunk {
    pub stream: Stream,
    pub bytes: Vec<u8>,
}

pub type ConsoleLog = Vec<Chunk>;

pub struct LaunchResult {
    pub exit_code: i32,
    pub console: ConsoleLog,
    pub new_pids: Vec<u32>,
    pub outlived: bool,
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Build a UTF-16 environment block from a sorted map (name=value\0 ... \0\0).
pub fn env_block(env: &std::collections::BTreeMap<String, String>) -> Vec<u16> {
    let mut out = Vec::new();
    for (k, v) in env {
        out.extend(format!("{}={}", k, v).encode_utf16());
        out.push(0);
    }
    out.push(0);
    out
}

unsafe fn make_inheritable_pipe() -> Result<(HANDLE, HANDLE)> {
    let mut read: HANDLE = std::ptr::null_mut();
    let mut write: HANDLE = std::ptr::null_mut();
    if CreatePipe(&mut read, &mut write, std::ptr::null(), 0) == 0 {
        return Err(anyhow!("CreatePipe failed"));
    }
    // Only the write end is inherited by the child; keep our read end private.
    SetHandleInformation(write, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    SetHandleInformation(read, HANDLE_FLAG_INHERIT, 0);
    Ok((read, write))
}

unsafe fn open_nul() -> HANDLE {
    let name = wide("NUL");
    CreateFileW(
        name.as_ptr(),
        windows_sys::Win32::Foundation::GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        std::ptr::null(),
        OPEN_EXISTING,
        0,
        std::ptr::null_mut(),
    )
}

/// Launch and wait. `app`/`cmdline` come from resolve; `dll_ansi` is the
/// injected hook path; `payload` carries the pipe name; `env` is the child env.
#[allow(clippy::too_many_arguments)]
pub fn launch(
    app: &Path,
    cmdline: &str,
    cwd: &str,
    dll_ansi: &[u8],
    payload: &RunPayload,
    env: &std::collections::BTreeMap<String, String>,
) -> Result<LaunchResult> {
    unsafe { launch_inner(app, cmdline, cwd, dll_ansi, payload, env) }
}

unsafe fn launch_inner(
    app: &Path,
    cmdline: &str,
    cwd: &str,
    dll_ansi: &[u8],
    payload: &RunPayload,
    env: &std::collections::BTreeMap<String, String>,
) -> Result<LaunchResult> {
    // --- job + completion port ---
    let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
    if job.is_null() {
        return Err(anyhow!("CreateJobObject failed"));
    }
    let port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, std::ptr::null_mut(), 0, 1);
    if port.is_null() {
        return Err(anyhow!("CreateIoCompletionPort failed"));
    }
    let assoc = JOBOBJECT_ASSOCIATE_COMPLETION_PORT {
        CompletionKey: job as *mut _,
        CompletionPort: port,
    };
    if SetInformationJobObject(
        job,
        JobObjectAssociateCompletionPortInformation,
        &assoc as *const _ as *const _,
        core::mem::size_of::<JOBOBJECT_ASSOCIATE_COMPLETION_PORT>() as u32,
    ) == 0
    {
        return Err(anyhow!("associate completion port failed"));
    }

    // --- stdio pipes ---
    let (out_r, out_w) = make_inheritable_pipe()?;
    let (err_r, err_w) = make_inheritable_pipe()?;
    let nul = open_nul();

    let mut si: STARTUPINFOW = core::mem::zeroed();
    si.cb = core::mem::size_of::<STARTUPINFOW>() as u32;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = nul;
    si.hStdOutput = out_w;
    si.hStdError = err_w;

    let mut pi: PROCESS_INFORMATION = core::mem::zeroed();

    let app_w = wide(&app.to_string_lossy());
    let mut cmd_w = wide(cmdline);
    let cwd_w = wide(cwd);
    let mut envblock = env_block(env);

    let ok = memo_detours::DetourCreateProcessWithDllExW(
        app_w.as_ptr(),
        cmd_w.as_mut_ptr(),
        std::ptr::null(),
        std::ptr::null(),
        1, // bInheritHandles
        CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
        envblock.as_mut_ptr() as *const _,
        cwd_w.as_ptr(),
        &si,
        &mut pi,
        dll_ansi.as_ptr(),
        std::ptr::null_mut(),
    );
    if ok == 0 {
        return Err(anyhow!(
            "failed to start process (DetourCreateProcessWithDllExW): {}",
            std::io::Error::last_os_error()
        ));
    }

    // Assign to the job (fires NEW_PROCESS for the root), copy the payload, then
    // resume so the injected DLL's DllMain runs with the payload in place.
    AssignProcessToJobObject(job, pi.hProcess);
    memo_detours::DetourCopyPayloadToProcess(
        pi.hProcess,
        &memo_detours::MEMO_GUID,
        payload.as_bytes().as_ptr() as *const _,
        core::mem::size_of::<RunPayload>() as u32,
    );

    // Close our copies of the child's write ends so our reads see EOF when the
    // child (and all inheritors) close theirs.
    CloseHandle(out_w);
    CloseHandle(err_w);

    // Console reader threads.
    let console: Arc<Mutex<ConsoleLog>> = Arc::new(Mutex::new(Vec::new()));
    let out_reader = spawn_reader(out_r, Stream::Out, console.clone());
    let err_reader = spawn_reader(err_r, Stream::Err, console.clone());

    ResumeThread(pi.hThread);

    // Wait for the root process to exit.
    WaitForSingleObject(pi.hProcess, INFINITE);
    let mut code: u32 = 0;
    GetExitCodeProcess(pi.hProcess, &mut code);

    // Drain the completion port for NEW_PROCESS ids and ACTIVE_PROCESS_ZERO,
    // giving the tree up to 2s to fully drain after the root exits.
    let mut new_pids = Vec::new();
    let mut zero = false;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        let mut bytes: u32 = 0;
        let mut key: usize = 0;
        let mut ov: *mut windows_sys::Win32::System::IO::OVERLAPPED = std::ptr::null_mut();
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        let timeout_ms = remaining.as_millis().min(2000) as u32;
        let got = GetQueuedCompletionStatus(port, &mut bytes, &mut key, &mut ov, timeout_ms);
        if got == 0 && ov.is_null() {
            // Timed out.
            break;
        }
        match bytes {
            JOB_OBJECT_MSG_NEW_PROCESS => {
                new_pids.push(ov as usize as u32);
            }
            JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO => {
                zero = true;
                break;
            }
            _ => {}
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
    }

    let outlived = !zero;
    if outlived {
        // A process is still alive after the grace period: kill the tree so we
        // don't hang, and let the caller taint the run.
        TerminateJobObject(job, 1);
    }

    // Reader threads finish when all write ends are closed (tree exited).
    let _ = out_reader.join();
    let _ = err_reader.join();

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(job);
    CloseHandle(port);
    CloseHandle(nul);

    let console = Arc::try_unwrap(console)
        .map(|m| m.into_inner().unwrap())
        .unwrap_or_default();

    Ok(LaunchResult {
        exit_code: code as i32,
        console,
        new_pids,
        outlived,
    })
}

fn spawn_reader(
    read_handle: HANDLE,
    stream: Stream,
    console: Arc<Mutex<ConsoleLog>>,
) -> std::thread::JoinHandle<()> {
    // Move the handle into the thread as an OwnedHandle so it's closed on exit.
    let owned = unsafe { OwnedHandle::from_raw_handle(read_handle as *mut _) };
    std::thread::spawn(move || {
        use std::io::Read;
        let mut file = std::fs::File::from(owned);
        let mut buf = [0u8; 16 * 1024];
        loop {
            match file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let data = &buf[..n];
                    // Live echo.
                    use std::io::Write;
                    match stream {
                        Stream::Out => {
                            let _ = std::io::stdout().write_all(data);
                            let _ = std::io::stdout().flush();
                        }
                        Stream::Err => {
                            let _ = std::io::stderr().write_all(data);
                            let _ = std::io::stderr().flush();
                        }
                    }
                    console.lock().unwrap().push(Chunk {
                        stream,
                        bytes: data.to_vec(),
                    });
                }
                Err(_) => break,
            }
        }
    })
}

/// Replay a console log to memo's real stdout/stderr in recorded order.
pub fn replay_console(log: &ConsoleLog) {
    use std::io::Write;
    let mut out = std::io::stdout();
    let mut err = std::io::stderr();
    for chunk in log {
        match chunk.stream {
            Stream::Out => {
                let _ = out.write_all(&chunk.bytes);
            }
            Stream::Err => {
                let _ = err.write_all(&chunk.bytes);
            }
        }
    }
    let _ = out.flush();
    let _ = err.flush();
}

/// Guard against an unused import warning for WAIT_OBJECT_0 (kept for clarity in
/// the wait logic's intent).
#[allow(dead_code)]
const _WAIT_OK: u32 = WAIT_OBJECT_0;
