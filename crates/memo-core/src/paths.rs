//! Path normalization and case-folded identity.
//!
//! memo compares paths case-insensitively (Windows default) but stores the
//! original spelling for I/O. [`PathId`] is the case-folded identity key.

/// Case-fold a path for identity comparison. Windows file systems are
/// case-insensitive (ASCII + most Unicode); we lowercase for a stable key.
pub fn case_fold(path: &str) -> String {
    path.to_lowercase()
}

/// Normalize a Win32 path: unify separators to `\`, collapse `.` and `..`
/// segments, and strip a trailing separator (except a bare drive root).
/// Preserves the original casing of the surviving segments.
pub fn normalize(path: &str) -> String {
    let unified = path.replace('/', "\\");

    // Preserve a leading prefix: drive (`C:`), UNC (`\\server\share`), or
    // verbatim (`\\?\`). We operate on the remainder.
    let bytes = unified.as_bytes();

    // Detect UNC / verbatim prefix.
    let (prefix, rest) = if unified.starts_with("\\\\") {
        // Keep the whole `\\server\share` or `\\?\...` head intact up to the
        // component after share; simplest correct handling: treat everything
        // as segments but keep the leading `\\`.
        ("\\\\", &unified[2..])
    } else if bytes.len() >= 2 && bytes[1] == b':' {
        // Drive-letter path like `C:\...` or `C:relative`.
        (&unified[..2], &unified[2..])
    } else {
        ("", unified.as_str())
    };

    let rooted = rest.starts_with('\\');
    let mut out: Vec<&str> = Vec::new();
    for seg in rest.split('\\') {
        match seg {
            "" | "." => continue,
            ".." => {
                // Pop unless we'd go above the root.
                if matches!(out.last(), Some(&s) if s != "..") {
                    out.pop();
                } else if prefix.is_empty() && !rooted {
                    out.push("..");
                }
            }
            s => out.push(s),
        }
    }

    let joined = out.join("\\");
    let mut result = String::new();
    result.push_str(prefix);
    if rooted {
        result.push('\\');
    }
    result.push_str(&joined);

    // A bare drive like `C:` with nothing else stays `C:`; `C:\` stays `C:\`.
    if result.is_empty() {
        ".".to_string()
    } else {
        result
    }
}

/// Case-folded, normalized identity key for a path.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PathId(pub String);

impl PathId {
    pub fn new(path: &str) -> Self {
        PathId(case_fold(&normalize(path)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_trailing_separator() {
        assert_eq!(normalize("C:\\a\\b\\"), "C:\\a\\b");
    }

    #[test]
    fn keeps_drive_root_backslash() {
        assert_eq!(normalize("C:\\"), "C:\\");
    }

    #[test]
    fn unifies_forward_slashes() {
        assert_eq!(normalize("C:/a/b"), "C:\\a\\b");
    }

    #[test]
    fn collapses_dot_segment() {
        assert_eq!(normalize("C:\\a\\.\\b"), "C:\\a\\b");
    }

    #[test]
    fn collapses_dotdot_segment() {
        assert_eq!(normalize("C:\\a\\b\\..\\c"), "C:\\a\\c");
    }

    #[test]
    fn preserves_unc_prefix() {
        assert_eq!(normalize("\\\\server\\share\\a\\"), "\\\\server\\share\\a");
    }

    #[test]
    fn case_fold_lowercases() {
        assert_eq!(case_fold("C:\\Foo\\Bar.TXT"), "c:\\foo\\bar.txt");
    }

    #[test]
    fn pathid_folds_and_normalizes() {
        assert_eq!(PathId::new("C:/Foo/./Bar/"), PathId::new("c:\\foo\\bar"));
    }
}
