//! Resolve a user command to an executable + command line, mirroring how the
//! shell would find it (PATH + PATHEXT), and routing `.cmd`/`.bat` through
//! cmd.exe.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedCommand {
    /// The executable to launch (the program itself, or cmd.exe for scripts).
    pub app: PathBuf,
    /// The full command line passed to CreateProcess.
    pub cmdline: String,
    /// Whether we wrapped the command in `cmd /d /s /c`.
    pub via_cmd: bool,
    /// The file whose content identifies the command's behavior (the exe or the
    /// script), used for the cache key's app hash.
    pub target: PathBuf,
}

/// Quote a single argument for a Windows command line (CommandLineToArgvW rules).
pub fn quote_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '\n', '\u{b}', '"']) {
        return arg.to_string();
    }
    let mut out = String::from("\"");
    let mut backslashes = 0usize;
    for c in arg.chars() {
        match c {
            '\\' => {
                backslashes += 1;
            }
            '"' => {
                out.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                backslashes = 0;
                out.push('"');
            }
            _ => {
                out.extend(std::iter::repeat_n('\\', backslashes));
                backslashes = 0;
                out.push(c);
            }
        }
    }
    out.extend(std::iter::repeat_n('\\', backslashes * 2));
    out.push('"');
    out
}

fn join_cmdline(argv: &[String]) -> String {
    argv.iter()
        .map(|a| quote_arg(a))
        .collect::<Vec<_>>()
        .join(" ")
}

fn pathext() -> Vec<String> {
    std::env::var("PATHEXT")
        .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string())
        .split(';')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_lowercase())
        .collect()
}

/// Find a program on PATH, honoring PATHEXT. Returns the resolved file path.
pub fn which(program: &str) -> Option<PathBuf> {
    let p = Path::new(program);

    // Explicit path (contains a separator) or has an extension that exists.
    if program.contains('\\') || program.contains('/') {
        if p.is_file() {
            return Some(p.to_path_buf());
        }
        // Try appending PATHEXT.
        for ext in pathext() {
            let cand = PathBuf::from(format!("{}{}", program, ext));
            if cand.is_file() {
                return Some(cand);
            }
        }
        return None;
    }

    let has_ext = p.extension().is_some();
    let dirs = std::env::var("PATH").unwrap_or_default();
    for dir in dirs.split(';').filter(|s| !s.is_empty()) {
        let base = Path::new(dir).join(program);
        if has_ext && base.is_file() {
            return Some(base);
        }
        for ext in pathext() {
            let cand = Path::new(dir).join(format!("{}{}", program, ext));
            if cand.is_file() {
                return Some(cand);
            }
        }
    }
    None
}

/// Resolve a full argv into a launchable command.
pub fn resolve(argv: &[String]) -> anyhow::Result<ResolvedCommand> {
    if argv.is_empty() {
        anyhow::bail!("no command given");
    }
    let program = &argv[0];
    let resolved =
        which(program).ok_or_else(|| anyhow::anyhow!("command not found on PATH: {}", program))?;

    let ext = resolved
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.to_lowercase())
        .unwrap_or_default();

    if ext == "cmd" || ext == "bat" {
        // Route through cmd.exe. cmd needs the whole thing as one /c argument.
        let comspec = std::env::var("ComSpec")
            .unwrap_or_else(|_| "C:\\Windows\\System32\\cmd.exe".to_string());
        // Rebuild argv with the resolved script path in slot 0.
        let mut full = argv.to_vec();
        full[0] = resolved.to_string_lossy().into_owned();
        let inner = join_cmdline(&full);
        // cmd /d /s /c "<inner>" — the surrounding quotes let cmd treat the
        // whole thing as one command (cmd's quote-stripping rules).
        let cmdline = format!("{} /d /s /c \"{}\"", quote_arg(&comspec), inner);
        Ok(ResolvedCommand {
            app: PathBuf::from(comspec),
            cmdline,
            via_cmd: true,
            target: resolved,
        })
    } else {
        let mut full = argv.to_vec();
        full[0] = resolved.to_string_lossy().into_owned();
        let cmdline = join_cmdline(&full);
        Ok(ResolvedCommand {
            app: resolved.clone(),
            cmdline,
            via_cmd: false,
            target: resolved,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_args_with_spaces() {
        assert_eq!(quote_arg("simple"), "simple");
        assert_eq!(quote_arg("has space"), "\"has space\"");
        assert_eq!(quote_arg(""), "\"\"");
    }

    #[test]
    fn quotes_embedded_quote() {
        assert_eq!(quote_arg("a\"b"), "\"a\\\"b\"");
    }

    #[test]
    fn resolves_cmd_on_path() {
        // cmd.exe is always present in System32, which is on PATH.
        let r = resolve(&["cmd".into(), "/c".into(), "echo hi".into()]).unwrap();
        assert!(r.app.to_string_lossy().to_lowercase().ends_with("cmd.exe"));
        assert!(!r.via_cmd);
    }

    #[test]
    fn unknown_command_errors() {
        assert!(resolve(&["definitely-not-a-real-prog-xyz".into()]).is_err());
    }

    #[test]
    fn bat_script_is_wrapped_in_cmd() {
        let dir = tempfile::tempdir().unwrap();
        let bat = dir.path().join("greet.bat");
        std::fs::write(&bat, b"@echo hello\r\n").unwrap();
        let r = resolve(&[bat.to_string_lossy().into_owned()]).unwrap();
        assert!(r.via_cmd);
        assert!(r.app.to_string_lossy().to_lowercase().ends_with("cmd.exe"));
        assert!(r.cmdline.to_lowercase().contains("/d /s /c"));
        assert_eq!(r.target, bat);
    }
}
