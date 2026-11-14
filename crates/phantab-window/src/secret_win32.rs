//! Windows OS calls for [`crate::secret_store`] (DPAPI) and [`crate::console`] (a line read with echo off).
//! SR-58: each `unsafe` block says why it is sound. Every buffer DPAPI allocates is wiped and freed by
//! [`OsBlob`] on every path.
#![allow(unsafe_code)]

use std::ffi::c_void;

use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};
use windows::Win32::System::Console::{
    CONSOLE_MODE, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT,
    ENABLE_VIRTUAL_TERMINAL_INPUT, GetConsoleMode, GetStdHandle, ReadConsoleW, STD_INPUT_HANDLE,
    SetConsoleMode,
};
use windows::core::PCWSTR;
use zeroize::{Zeroize as _, Zeroizing};

use crate::console_keys::{Line, Step};

/// A blob DPAPI allocated with `LocalAlloc`: wiped, then freed, on drop.
struct OsBlob(CRYPT_INTEGER_BLOB);

impl OsBlob {
    fn empty() -> Self {
        Self(CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() })
    }

    fn bytes(&self) -> &[u8] {
        if self.0.pbData.is_null() || self.0.cbData == 0 {
            return &[];
        }
        // SAFETY: DPAPI filled `pbData` with `cbData` initialised bytes it owns until LocalFree in drop;
        // the borrow cannot outlive `self`.
        unsafe { std::slice::from_raw_parts(self.0.pbData, self.0.cbData as usize) }
    }
}

impl Drop for OsBlob {
    fn drop(&mut self) {
        if self.0.pbData.is_null() {
            return;
        }
        // SAFETY: as in `bytes`, the region is `cbData` bytes DPAPI allocated and nobody else holds; it is
        // wiped once, then freed once, here.
        unsafe {
            std::slice::from_raw_parts_mut(self.0.pbData, self.0.cbData as usize).zeroize();
            let _ = LocalFree(Some(HLOCAL(self.0.pbData.cast::<c_void>())));
        }
    }
}

/// A read-only blob over caller memory: DPAPI takes `*const` input and does not write to it.
fn input(bytes: &[u8]) -> std::io::Result<CRYPT_INTEGER_BLOB> {
    let len = u32::try_from(bytes.len()).map_err(|_| std::io::Error::other("secret too large for DPAPI"))?;
    Ok(CRYPT_INTEGER_BLOB { cbData: len, pbData: bytes.as_ptr().cast_mut() })
}

pub(crate) fn protect(plain: &[u8], entropy: &[u8]) -> std::io::Result<Vec<u8>> {
    let data = input(plain)?;
    let salt = input(entropy)?;
    let mut out = OsBlob::empty();
    // SAFETY: `data` and `salt` point into the borrowed slices, alive for the call, which DPAPI only reads;
    // `out` receives a LocalAlloc buffer that OsBlob frees. No prompt (UI_FORBIDDEN), no description.
    unsafe {
        CryptProtectData(
            &raw const data,
            PCWSTR::null(),
            Some(&raw const salt),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &raw mut out.0,
        )
    }
    .map_err(|e| std::io::Error::other(format!("DPAPI protect failed: {}", e.code())))?;
    Ok(out.bytes().to_vec())
}

pub(crate) fn unprotect(blob: &[u8], entropy: &[u8]) -> std::io::Result<Zeroizing<Vec<u8>>> {
    let data = input(blob)?;
    let salt = input(entropy)?;
    let mut out = OsBlob::empty();
    // SAFETY: as in `protect`; the plaintext lands in a LocalAlloc buffer that OsBlob wipes and frees.
    unsafe {
        CryptUnprotectData(
            &raw const data,
            None,
            Some(&raw const salt),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &raw mut out.0,
        )
    }
    .map_err(|e| std::io::Error::other(format!("DPAPI unprotect failed: {}", e.code())))?;
    Ok(Zeroizing::new(out.bytes().to_vec()))
}

/// Puts the console's input mode back however the read ends.
struct RestoreMode(windows::Win32::Foundation::HANDLE, CONSOLE_MODE);

impl Drop for RestoreMode {
    fn drop(&mut self) {
        // SAFETY: the handle is this process's standard input console handle, read from GetStdHandle; the
        // mode is the one GetConsoleMode returned for it.
        let _ = unsafe { SetConsoleMode(self.0, self.1) };
    }
}

/// Longest line read, in UTF-16 units: far past any master password, short of an unbounded paste.
const MAX_LINE: usize = 1024;

/// The console mode for the hidden read: no echo, no line editing (the console's editor would echo
/// nothing but still handle keys phantab cannot see), no processed input (so Ctrl+C arrives as the unit
/// 0x03 instead of a `CTRL_C_EVENT` that ends the process with echo off), and no virtual-terminal input
/// (arrow keys then send nothing). [`crate::console_keys`] decides what each unit means; the drop guard
/// restores the saved mode. Ctrl+Break is still a signal the console always raises; it ends the process
/// without the guard, and the shell's next prompt sets its own mode again.
fn hidden_mode(mode: CONSOLE_MODE) -> CONSOLE_MODE {
    CONSOLE_MODE(
        mode.0
            & !(ENABLE_ECHO_INPUT.0
                | ENABLE_LINE_INPUT.0
                | ENABLE_PROCESSED_INPUT.0
                | ENABLE_VIRTUAL_TERMINAL_INPUT.0),
    )
}

pub(crate) fn read_hidden_line() -> std::io::Result<Zeroizing<String>> {
    let not_console = || {
        std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "standard input is not a Windows console (run this in Windows Terminal, PowerShell or cmd, not \
             a mintty/Git Bash window or a pipe)",
        )
    };
    // SAFETY: GetStdHandle only reads the process's standard-handle table.
    let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) }.map_err(|_| not_console())?;
    let mut mode = CONSOLE_MODE(0);
    // SAFETY: `mode` is a live out-parameter; a handle that is not a console makes the call fail.
    unsafe { GetConsoleMode(handle, &raw mut mode) }.map_err(|_| not_console())?;
    let restore = RestoreMode(handle, mode);
    let hidden = hidden_mode(mode);
    // SAFETY: the same console handle; `restore` puts the old mode back on every path.
    unsafe { SetConsoleMode(handle, hidden) }.map_err(std::io::Error::other)?;

    let mut line: Line<u16> = Line::new(MAX_LINE);
    let mut chunk: Zeroizing<[u16; 256]> = Zeroizing::new([0; 256]);
    'read: loop {
        let mut read = 0u32;
        // SAFETY: `chunk` is a live buffer of exactly 256 UTF-16 units and `read` a live out-parameter;
        // the console writes at most that many units.
        unsafe { ReadConsoleW(handle, chunk.as_mut_ptr().cast::<c_void>(), 256, &raw mut read, None) }
            .map_err(std::io::Error::other)?;
        let got = &chunk[..(read as usize).min(chunk.len())];
        if got.is_empty() {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }
        for &unit in got {
            match line.feed(unit) {
                Step::More => {}
                Step::Done => break 'read,
                Step::Cancelled => return Err(crate::console::cancelled()),
                Step::Ended => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
                Step::TooLong => return Err(std::io::Error::other("input line too long")),
            }
        }
    }
    drop(restore);
    let mut text = Zeroizing::new(String::with_capacity(line.units().len() * 3));
    for c in char::decode_utf16(line.units().iter().copied()) {
        text.push(c.map_err(|_| std::io::Error::other("input is not valid text"))?);
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use windows::Win32::System::Console::{
        ENABLE_EXTENDED_FLAGS, ENABLE_INSERT_MODE, ENABLE_QUICK_EDIT_MODE,
    };

    use super::*;

    #[test]
    fn the_hidden_mode_turns_off_echo_editing_and_ctrl_c() {
        let kept = ENABLE_EXTENDED_FLAGS.0 | ENABLE_INSERT_MODE.0 | ENABLE_QUICK_EDIT_MODE.0;
        let off = ENABLE_ECHO_INPUT.0
            | ENABLE_LINE_INPUT.0
            | ENABLE_PROCESSED_INPUT.0
            | ENABLE_VIRTUAL_TERMINAL_INPUT.0;
        assert_eq!(hidden_mode(CONSOLE_MODE(kept | off)), CONSOLE_MODE(kept));
        assert_eq!(hidden_mode(CONSOLE_MODE(0)), CONSOLE_MODE(0));
    }
}
