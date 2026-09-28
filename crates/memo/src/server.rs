//! Named-pipe server: accepts a connection from every traced process and folds
//! its messages into the shared RunState, acking PreMutate after snapshotting.

use crate::collect::RunState;
use anyhow::{anyhow, Result};
use memo_proto::{read_msg, Msg, ACK};
use std::io::Write;
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use windows_sys::Win32::Foundation::{
    CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, OPEN_EXISTING, PIPE_ACCESS_DUPLEX};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};

const BUF: u32 = 64 * 1024;

pub struct PipeServer {
    name: String,
    shutdown: Arc<AtomicBool>,
    listener: Option<std::thread::JoinHandle<()>>,
    handlers: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

unsafe fn create_instance(name_w: &[u16]) -> HANDLE {
    CreateNamedPipeW(
        name_w.as_ptr(),
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        BUF,
        BUF,
        0,
        std::ptr::null(),
    )
}

impl PipeServer {
    /// Start accepting connections on a uniquely named pipe.
    pub fn start(name: String, state: Arc<Mutex<RunState>>) -> Result<PipeServer> {
        let name_w = wide(&name);
        // Validate we can create at least one instance up front.
        let probe = unsafe { create_instance(&name_w) };
        if probe == INVALID_HANDLE_VALUE || probe.is_null() {
            return Err(anyhow!(
                "CreateNamedPipe failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        let shutdown = Arc::new(AtomicBool::new(false));
        let handlers: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>> =
            Arc::new(Mutex::new(Vec::new()));

        let listener = {
            let name = name.clone();
            let shutdown = shutdown.clone();
            let handlers = handlers.clone();
            let state = state.clone();
            let probe_usize = probe as usize;
            std::thread::spawn(move || {
                let name_w = wide(&name);
                let mut instance = probe_usize as HANDLE;
                loop {
                    // Wait for a client on the current instance.
                    let connected = unsafe { ConnectNamedPipe(instance, std::ptr::null_mut()) };
                    let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                    // ERROR_PIPE_CONNECTED (535) means a client connected before
                    // ConnectNamedPipe; treat as success.
                    let ok = connected != 0 || err == 535;

                    if shutdown.load(Ordering::SeqCst) {
                        unsafe {
                            DisconnectNamedPipe(instance);
                            CloseHandle(instance);
                        }
                        break;
                    }

                    if ok {
                        let h_usize = instance as usize;
                        let st = state.clone();
                        let jh = std::thread::spawn(move || handle_client(h_usize as HANDLE, st));
                        handlers.lock().unwrap().push(jh);
                    } else {
                        unsafe { CloseHandle(instance) };
                    }

                    // Create the next instance for the next client.
                    instance = unsafe { create_instance(&name_w) };
                    if instance == INVALID_HANDLE_VALUE || instance.is_null() {
                        break;
                    }
                }
            })
        };

        Ok(PipeServer {
            name,
            shutdown,
            listener: Some(listener),
            handlers,
        })
    }

    /// Stop accepting and join all handlers. Unblocks the listener's pending
    /// ConnectNamedPipe by opening a throwaway client connection.
    pub fn shutdown(mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        // Poke the pipe to unblock ConnectNamedPipe.
        let name_w = wide(&self.name);
        unsafe {
            let h = CreateFileW(
                name_w.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            );
            if h != INVALID_HANDLE_VALUE && !h.is_null() {
                CloseHandle(h);
            }
        }
        if let Some(l) = self.listener.take() {
            let _ = l.join();
        }
        let handlers = std::mem::take(&mut *self.handlers.lock().unwrap());
        for h in handlers {
            let _ = h.join();
        }
    }
}

fn handle_client(pipe: HANDLE, state: Arc<Mutex<RunState>>) {
    // Own the handle so it's closed when this handler ends.
    let owned = unsafe { OwnedHandle::from_raw_handle(pipe as *mut _) };
    let file = std::fs::File::from(owned);
    let mut reader = &file;
    loop {
        match read_msg(&mut reader) {
            Ok(Some(msg)) => {
                let needs_ack = matches!(msg, Msg::PreMutate { .. });
                apply(&state, msg);
                if needs_ack {
                    // Snapshot is done; release the client.
                    let _ = (&file).write_all(&[ACK]);
                }
            }
            Ok(None) => break, // client closed
            Err(_) => break,
        }
    }
}

fn apply(state: &Arc<Mutex<RunState>>, msg: Msg) {
    let mut s = state.lock().unwrap();
    match msg {
        Msg::Hello { pid, .. } => s.on_hello(pid),
        Msg::Access { kind, path, .. } => s.on_access(kind, &path),
        Msg::PreMutate { path, .. } => s.on_premutate(&path),
        Msg::Mutate {
            kind, path, target, ..
        } => s.on_mutate(kind, &path, target.as_deref()),
        Msg::Taint { reason, detail, .. } => s.on_taint(reason, detail),
        Msg::ChildSpawned { .. } => {}
        Msg::Bye { .. } => {}
    }
}
