//! memo-probe — a scriptable test fixture that performs specific file/process/
//! network operations so integration tests can verify memo traces and replays
//! them. Each argument is one operation `op=arg` (or `op=a|b`). At startup, if
//! MEMO_PROBE_MARKER is set, it appends one byte to that file — so tests can tell
//! a real execution (marker grows) from a replay (marker unchanged).

use std::io::Write;

fn main() {
    // Mark a real execution (marker lives in an ignored temp path).
    if let Ok(marker) = std::env::var("MEMO_PROBE_MARKER") {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&marker)
        {
            let _ = f.write_all(b"x");
        }
    }

    let mut exit_code = 0i32;
    for arg in std::env::args().skip(1) {
        let (op, rest) = match arg.split_once('=') {
            Some((o, r)) => (o, r),
            None => continue,
        };
        match op {
            "read" => {
                let data = std::fs::read(rest).unwrap_or_default();
                println!("READ {} {}", rest, data.len());
            }
            "probe" => {
                let exists = std::path::Path::new(rest).exists();
                println!("PROBE {} {}", rest, exists);
            }
            "list" => {
                let mut names: Vec<String> = std::fs::read_dir(rest)
                    .map(|rd| {
                        rd.flatten()
                            .map(|e| e.file_name().to_string_lossy().into_owned())
                            .collect()
                    })
                    .unwrap_or_default();
                names.sort();
                println!("LIST {} {}", rest, names.join(","));
            }
            "write" => {
                let (path, text) = rest.split_once('|').unwrap_or((rest, ""));
                std::fs::write(path, text.as_bytes()).unwrap();
                println!("WROTE {} {}", path, text.len());
            }
            "trywrite" => {
                // Like write, but a failure is reported instead of panicking.
                let (path, text) = rest.split_once('|').unwrap_or((rest, ""));
                let ok = std::fs::write(path, text.as_bytes()).is_ok();
                println!("TRYWROTE {} {}", path, ok);
            }
            "append" => {
                let (path, text) = rest.split_once('|').unwrap_or((rest, ""));
                let mut f = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .unwrap();
                f.write_all(text.as_bytes()).unwrap();
                println!("APPENDED {} {}", path, text.len());
            }
            "delete" => {
                let _ = std::fs::remove_file(rest);
                println!("DELETED {}", rest);
            }
            "mkdir" => {
                let _ = std::fs::create_dir_all(rest);
                println!("MKDIR {}", rest);
            }
            "rename" => {
                let (from, to) = rest.split_once('|').unwrap_or((rest, ""));
                let _ = std::fs::rename(from, to);
                println!("RENAMED {} {}", from, to);
            }
            "mtio" => {
                // mtio=<in>|<out>: races a *normal* (non-abrupt) multithreaded
                // scenario against memo_hook's CLIENT lock, to check that
                // hook messages are never silently dropped during ordinary
                // operation. A writer thread does 50 writes to <out> -- each
                // write's premutate_wait holds CLIENT across a full ack
                // round-trip with memo -- while, right after the writer's
                // first write, this thread does exactly one read of <in>
                // (one attempt, not a loop: if that single Access::Read were
                // ever dropped by a contended lock, memo would never learn
                // <in> is an input, and a later run with <in> changed would
                // wrongly replay from cache instead of missing).
                let (in_path, out_path) = rest.split_once('|').unwrap_or((rest, ""));
                let in_path = in_path.to_string();
                let out_path = out_path.to_string();
                let started = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                let started_writer = started.clone();
                let out_path_writer = out_path.clone();
                let writer = std::thread::spawn(move || {
                    for i in 0..50 {
                        let _ = std::fs::write(&out_path_writer, format!("mtio-{}", i).as_bytes());
                        if i == 0 {
                            started_writer.store(true, std::sync::atomic::Ordering::SeqCst);
                        }
                    }
                });
                while !started.load(std::sync::atomic::Ordering::SeqCst) {
                    std::thread::yield_now();
                }
                let _ = std::fs::read(&in_path);
                writer.join().unwrap();
                println!("MTIO {} {}", in_path, out_path);
            }
            "threads" => {
                // threads=<n>: spawn n threads that each hammer a small
                // (Cargo.toml-sized), hooked file with opens/reads, then the
                // main thread exits abruptly (no join) while they're still
                // running. This reproduces the DLL_PROCESS_DETACH condition
                // that must never block: other threads live and mid file-I/O
                // (so possibly holding memo_hook's client lock) when
                // ExitProcess tears the process down.
                let n: usize = rest.parse().unwrap_or(0);
                println!("THREADS {}", n);
                // A fixed name (not per-pid): this process exits abruptly by
                // design and never removes the file, so a per-pid name would
                // leave one orphaned temp file behind per run.
                let path = std::env::temp_dir().join("memo-probe-threads.tmp");
                // Cargo.toml-sized: a small file, not empty, not huge.
                std::fs::write(&path, vec![b'x'; 1400]).unwrap();

                let started = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
                for _ in 0..n {
                    let path = path.clone();
                    let started = started.clone();
                    std::thread::spawn(move || {
                        for i in 0..200 {
                            let _ = std::fs::read(&path);
                            if i == 0 {
                                started.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            }
                        }
                    });
                }
                // Make sure every thread has actually performed at least one
                // hooked file op before we exit, so the abrupt exit races
                // against live, in-flight hook activity rather than threads
                // that never got scheduled.
                while started.load(std::sync::atomic::Ordering::SeqCst) < n {
                    std::thread::yield_now();
                }
                std::process::exit(0);
            }
            "spawn" => {
                // Spawn ourselves to run one op in a child process.
                let exe = std::env::current_exe().unwrap();
                let status = std::process::Command::new(exe)
                    .arg(rest)
                    .status()
                    .expect("spawn child");
                println!("SPAWNED {} {}", rest, status.code().unwrap_or(-1));
            }
            "net" => {
                use std::net::TcpStream;
                use std::time::Duration;
                let addr: std::net::SocketAddr = rest
                    .parse()
                    .unwrap_or_else(|_| "127.0.0.1:9".parse().unwrap());
                let _ = TcpStream::connect_timeout(&addr, Duration::from_millis(200));
                println!("NET {}", rest);
            }
            "bind" => {
                // A socket that is created and bound but never connects or
                // sends: not network access, so it must stay cacheable.
                let _ = std::net::UdpSocket::bind(rest);
                println!("BIND {}", rest);
            }
            "connectex" => {
                connect_ex(rest);
                println!("CONNECTEX {}", rest);
            }
            "concat" => {
                // concat=<a>|<b>|<out>: out = contents(a) ++ contents(b).
                let parts: Vec<&str> = rest.split('|').collect();
                let a = std::fs::read(parts[0]).unwrap_or_default();
                let b = parts
                    .get(1)
                    .map(|p| std::fs::read(p).unwrap_or_default())
                    .unwrap_or_default();
                let mut out = a.clone();
                out.extend_from_slice(&b);
                if let Some(dest) = parts.get(2) {
                    std::fs::write(dest, &out).unwrap();
                }
                println!("CONCAT {} {} {}", a.len(), b.len(), out.len());
            }
            "print" => {
                println!("{}", rest);
            }
            "eprint" => {
                eprintln!("{}", rest);
            }
            "exit" => {
                exit_code = rest.parse().unwrap_or(0);
            }
            "ctrlc" => {
                // ctrlc=swallow: handle Ctrl+C and keep going, like a test
                // runner that catches SIGINT and exits 0 with partial output.
                // ctrlc=enable: clear an inherited ignore-Ctrl+C flag (set on
                // every descendant of a CREATE_NEW_PROCESS_GROUP process).
                use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
                unsafe {
                    if rest == "enable" {
                        SetConsoleCtrlHandler(None, 0)
                    } else {
                        SetConsoleCtrlHandler(Some(swallow), 1)
                    }
                };
                println!("CTRLC {}", rest);
            }
            "ready" => {
                // ready=<path>: signal the test (put it under %TEMP%, which
                // memo ignores).
                let _ = std::fs::write(rest, b"");
            }
            "sleep" => {
                let ms = rest.parse().unwrap_or(0);
                std::thread::sleep(std::time::Duration::from_millis(ms));
            }
            "sendctrl" => {
                // sendctrl=<c|break>:<pid>: deliver Ctrl+C or Ctrl+Break to
                // every process on <pid>'s console, as a keypress would. Not
                // run under memo.
                use windows_sys::Win32::System::Console::*;
                let (kind, pid) = rest.split_once(':').unwrap_or(("c", rest));
                let event = if kind == "break" {
                    CTRL_BREAK_EVENT
                } else {
                    CTRL_C_EVENT
                };
                let pid: u32 = pid.parse().unwrap_or(0);
                let ok = unsafe {
                    FreeConsole();
                    // Swallow it ourselves: the event reaches every process on
                    // the console, us included, and the NULL-handler ignore
                    // flag covers only Ctrl+C, not Ctrl+Break.
                    AttachConsole(pid) != 0
                        && SetConsoleCtrlHandler(Some(swallow), 1) != 0
                        && GenerateConsoleCtrlEvent(event, 0) != 0
                };
                // stdout may be gone after FreeConsole; the exit code reports.
                exit_code = if ok { 0 } else { 1 };
            }
            _ => {}
        }
    }
    std::process::exit(exit_code);
}

/// Console control handler that handles every event (the process keeps going).
unsafe extern "system" fn swallow(_: u32) -> i32 {
    1
}

/// TCP connect via ConnectEx, the path libuv (so Node) uses. At the AFD layer
/// it is a different request from connect(). Connect only, no data sent, so a
/// send can't stand in for a missed connect.
fn connect_ex(addr: &str) {
    use std::mem::{size_of, zeroed};
    use std::ptr::{null, null_mut};
    use windows_sys::core::GUID;
    use windows_sys::Win32::Networking::WinSock::*;
    use windows_sys::Win32::System::IO::OVERLAPPED;

    let target: std::net::SocketAddrV4 = addr
        .parse()
        .unwrap_or_else(|_| "127.0.0.1:9".parse().unwrap());
    unsafe {
        let mut wsa: WSADATA = zeroed();
        WSAStartup(0x0202, &mut wsa);
        let s = socket(AF_INET as i32, SOCK_STREAM, IPPROTO_TCP);
        // ConnectEx requires a bound socket.
        let mut local: SOCKADDR_IN = zeroed();
        local.sin_family = AF_INET;
        bind(
            s,
            &local as *const _ as *const SOCKADDR,
            size_of::<SOCKADDR_IN>() as i32,
        );

        let guid: GUID = WSAID_CONNECTEX;
        let mut connect_ex: LPFN_CONNECTEX = None;
        let mut bytes = 0u32;
        WSAIoctl(
            s,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            &guid as *const _ as *const _,
            size_of::<GUID>() as u32,
            &mut connect_ex as *mut _ as *mut _,
            size_of::<LPFN_CONNECTEX>() as u32,
            &mut bytes,
            null_mut(),
            None,
        );

        let mut remote: SOCKADDR_IN = zeroed();
        remote.sin_family = AF_INET;
        remote.sin_port = target.port().to_be();
        remote.sin_addr.S_un.S_addr = u32::from_ne_bytes(target.ip().octets());
        // Leaked: the kernel may still complete into it after closesocket.
        let ov: &mut OVERLAPPED = Box::leak(Box::new(zeroed()));
        ov.hEvent = WSACreateEvent() as *mut _;
        if let Some(f) = connect_ex {
            f(
                s,
                &remote as *const _ as *const SOCKADDR,
                size_of::<SOCKADDR_IN>() as i32,
                null(),
                0,
                null_mut(),
                ov,
            );
            WSAWaitForMultipleEvents(1, &ov.hEvent, 1, 1000, 0);
        }
        closesocket(s);
    }
}
