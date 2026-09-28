//! Ctrl+C while the command runs (spec §10). The command shares memo's console
//! and gets the event itself; memo stays alive to collect its output and exit
//! code, and marks the run interrupted so it is never cached. (The hook also
//! reports the event from inside each traced process, which covers a command
//! that handles it and exits before this handler runs.)

use std::sync::atomic::{AtomicBool, Ordering};
use windows_sys::Win32::Foundation::BOOL;
use windows_sys::Win32::System::Console::{SetConsoleCtrlHandler, CTRL_BREAK_EVENT, CTRL_C_EVENT};

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

unsafe extern "system" fn on_ctrl(ctrl: u32) -> BOOL {
    if ctrl == CTRL_C_EVENT || ctrl == CTRL_BREAK_EVENT {
        INTERRUPTED.store(true, Ordering::SeqCst);
        1 // handled: memo keeps running
    } else {
        0 // close/logoff/shutdown: default handling (memo exits, nothing stored)
    }
}

/// Keeps memo alive through Ctrl+C/Ctrl+Break while it exists. A real handler,
/// not SetConsoleCtrlHandler(NULL, TRUE): that flag is inherited by child
/// processes and would make the command itself ignore Ctrl+C.
pub struct Guard;

impl Guard {
    pub fn install() -> Guard {
        INTERRUPTED.store(false, Ordering::SeqCst);
        unsafe { SetConsoleCtrlHandler(Some(on_ctrl), 1) };
        Guard
    }

    pub fn interrupted(&self) -> bool {
        INTERRUPTED.load(Ordering::SeqCst)
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        unsafe { SetConsoleCtrlHandler(Some(on_ctrl), 0) };
    }
}
