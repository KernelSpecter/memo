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
    let (prefix, rest) = if let Some(rest) = unified.strip_prefix("\\\\") {
        // Keep the whole `\\server\share` or `\\?\...` head intact up to the
        // component after share; simplest correct handling: treat everything
        // as segments but keep the leading `\\`.
        ("\\\\", rest)
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

/// Maps NT device names (`\Device\HarddiskVolumeN`) to DOS drive letters.
#[derive(Debug, Clone, Default)]
pub struct VolumeMap {
    /// (device path lowercased, drive letter) e.g. ("\\device\\harddiskvolume2", 'c')
    entries: Vec<(String, char)>,
}

impl VolumeMap {
    /// Build from explicit pairs (used in tests).
    pub fn from_pairs(pairs: &[(&str, char)]) -> Self {
        VolumeMap {
            entries: pairs.iter().map(|(d, c)| (d.to_lowercase(), *c)).collect(),
        }
    }

    /// Query the live system with `QueryDosDeviceW` over A–Z.
    #[cfg(windows)]
    pub fn from_system() -> Self {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::QueryDosDeviceW;

        let mut entries = Vec::new();
        for letter in b'A'..=b'Z' {
            let dos = format!("{}:", letter as char);
            let wide: Vec<u16> = std::ffi::OsStr::new(&dos)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            let mut target = [0u16; 512];
            let n =
                unsafe { QueryDosDeviceW(wide.as_ptr(), target.as_mut_ptr(), target.len() as u32) };
            if n > 0 {
                // The result may contain multiple NUL-separated strings; take
                // the first.
                let end = target.iter().position(|&c| c == 0).unwrap_or(0);
                let dev = String::from_utf16_lossy(&target[..end]);
                if !dev.is_empty() {
                    entries.push((dev.to_lowercase(), letter as char));
                }
            }
        }
        VolumeMap { entries }
    }

    #[cfg(not(windows))]
    pub fn from_system() -> Self {
        VolumeMap::default()
    }

    /// Resolve a `\Device\HarddiskVolumeN`-style prefix to a drive letter.
    pub fn device_to_drive(&self, device: &str) -> Option<char> {
        let dl = device.to_lowercase();
        self.entries.iter().find(|(d, _)| *d == dl).map(|(_, c)| *c)
    }
}

/// Result of classifying an NT path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Classified {
    /// A real filesystem path in Win32 form (normalized, original casing).
    File(String),
    /// A non-filesystem device (pipe, console, socket, nul, ...). Not tracked.
    Device,
    /// An NT path we can't map to a stable Win32 path (a volume without a drive
    /// letter, an unknown HarddiskVolume, some other `\Device\`/`\??\` object).
    /// It might be a real file we'd fail to fingerprint, so the caller taints
    /// rather than tracking it as a relative file or silently ignoring it.
    Unknown(String),
}

/// Convert an NT-namespace path to a Win32 path, or classify it as a device.
///
/// Handles `\??\C:\..`, `\??\UNC\..`, `\Device\HarddiskVolumeN\..`, and the
/// common non-filesystem devices. Already-Win32 paths pass through normalized.
pub fn from_nt(nt: &str, vols: &VolumeMap) -> Classified {
    let lower = nt.to_lowercase();

    // Non-filesystem devices and reserved names.
    const DEVICES: &[&str] = &[
        "\\device\\namedpipe",
        "\\device\\condrv",
        "\\device\\afd",
        "\\device\\ksecdd",
        "\\device\\cng",
        "\\device\\mup",
        "\\device\\null",
        "\\device\\tcp",
        "\\device\\udp",
        "\\device\\nsi",
    ];
    for d in DEVICES {
        if lower == *d || lower.starts_with(&format!("{}\\", d)) {
            return Classified::Device;
        }
    }
    // Reserved DOS names and pipe aliases.
    let tail = lower.trim_start_matches("\\??\\");
    if matches!(
        tail,
        "nul" | "con" | "conin$" | "conout$" | "mountpointmanager"
    ) || tail.starts_with("pipe\\")
        || tail == "pipe"
    {
        return Classified::Device;
    }

    // \??\ prefix: DOS-device path.
    if let Some(rest) = strip_prefix_ci(nt, "\\??\\") {
        if let Some(unc) = strip_prefix_ci(rest, "UNC\\") {
            return Classified::File(normalize(&format!("\\\\{}", unc)));
        }
        if is_drive_path(rest) {
            return Classified::File(normalize(rest));
        }
        // A bare DOS-device name — \??\Nsi, \??\Tcp, \??\MountPointManager,
        // \??\PhysicalDrive0, \??\Volume{GUID} — is a device object, not a file:
        // ignore it. A path THROUGH an unmapped object (\??\Volume{GUID}\file)
        // could be a real file we can't map to a stable key, so taint (Unknown)
        // rather than resolving it against memo's cwd as a relative path.
        if !rest.contains('\\') {
            return Classified::Device;
        }
        return Classified::Unknown(nt.to_string());
    }

    // \Device\HarddiskVolumeN\rest → X:\rest
    if lower.starts_with("\\device\\harddiskvolume") {
        // Split into device prefix (up to the 3rd backslash) and the rest.
        // nt = \Device\HarddiskVolume2\path\to\file
        let parts: Vec<&str> = nt.splitn(4, '\\').collect();
        // parts = ["", "Device", "HarddiskVolume2", "path\\to\\file"]
        if parts.len() >= 3 {
            let device = format!("\\{}\\{}", parts[1], parts[2]);
            if let Some(drive) = vols.device_to_drive(&device) {
                let rest = parts.get(3).copied().unwrap_or("");
                return Classified::File(normalize(&format!("{}:\\{}", drive, rest)));
            }
        }
        // Unknown volume: we can't map it to a stable path, and it may hold a
        // real file — taint rather than silently dropping it.
        return Classified::Unknown(nt.to_string());
    }

    // Already a Win32 UNC or drive path.
    if nt.starts_with("\\\\") || (nt.len() >= 2 && nt.as_bytes()[1] == b':') {
        return Classified::File(normalize(nt));
    }

    // Anything else NT-namespaced we don't understand: it isn't a device we
    // recognize and we can't map it to a Win32 path — taint rather than ignore.
    if nt.starts_with("\\Device\\") || nt.starts_with("\\??\\") {
        return Classified::Unknown(nt.to_string());
    }

    // Fallback: relative or odd — normalize and treat as file.
    Classified::File(normalize(nt))
}

/// Whether `p` begins with a `X:` drive spec.
fn is_drive_path(p: &str) -> bool {
    let b = p.as_bytes();
    b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic()
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
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

    fn vols() -> VolumeMap {
        VolumeMap::from_pairs(&[("\\Device\\HarddiskVolume2", 'C')])
    }

    #[test]
    fn nt_dosdevice_drive() {
        assert_eq!(
            from_nt("\\??\\C:\\proj\\a.txt", &vols()),
            Classified::File("C:\\proj\\a.txt".into())
        );
    }

    #[test]
    fn nt_dosdevice_unc() {
        assert_eq!(
            from_nt("\\??\\UNC\\server\\share\\x", &vols()),
            Classified::File("\\\\server\\share\\x".into())
        );
    }

    #[test]
    fn nt_harddisk_volume_maps_to_drive() {
        assert_eq!(
            from_nt("\\Device\\HarddiskVolume2\\proj\\a.txt", &vols()),
            Classified::File("C:\\proj\\a.txt".into())
        );
    }

    #[test]
    fn nt_unmappable_paths_are_unknown() {
        // An unknown HarddiskVolume can't be mapped to a drive — taint, don't
        // silently drop (it may hold a real file).
        assert!(matches!(
            from_nt("\\Device\\HarddiskVolume9\\x", &vols()),
            Classified::Unknown(_)
        ));
        // A volume without a drive letter is not a relative file.
        assert!(matches!(
            from_nt("\\??\\Volume{abc}\\x", &vols()),
            Classified::Unknown(_)
        ));
        // MountPointManager is a known control device (ignored, not tainted).
        assert_eq!(
            from_nt("\\??\\MountPointManager", &vols()),
            Classified::Device
        );
    }

    #[test]
    fn named_pipe_is_device() {
        assert_eq!(
            from_nt("\\Device\\NamedPipe\\foo", &vols()),
            Classified::Device
        );
    }

    #[test]
    fn condrv_is_device() {
        assert_eq!(
            from_nt("\\Device\\ConDrv\\Console", &vols()),
            Classified::Device
        );
    }

    #[test]
    fn afd_socket_is_device() {
        assert_eq!(
            from_nt("\\Device\\Afd\\Endpoint", &vols()),
            Classified::Device
        );
    }

    #[test]
    fn nul_is_device() {
        assert_eq!(from_nt("\\??\\NUL", &vols()), Classified::Device);
    }

    #[test]
    fn plain_win32_path_passes_through() {
        assert_eq!(
            from_nt("C:\\already\\win32", &vols()),
            Classified::File("C:\\already\\win32".into())
        );
    }
}
