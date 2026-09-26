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
            "print" => {
                println!("{}", rest);
            }
            "eprint" => {
                eprintln!("{}", rest);
            }
            "exit" => {
                exit_code = rest.parse().unwrap_or(0);
            }
            _ => {}
        }
    }
    std::process::exit(exit_code);
}
