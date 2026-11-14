//! Unix OS calls for [`crate::console`]: one line from the terminal on standard input with echo off.
//! SR-58: each `unsafe` block says why it is sound.
//!
//! The terminal is put in non-canonical mode with echo, signal keys (`ISIG`) and extended keys (`IEXTEN`)
//! off, so Ctrl+C reaches the reader as the byte 0x03 instead of killing the process with echo still off;
//! [`crate::console_keys`] decides what each byte means. The drop guard restores the saved settings on
//! every return. A signal from elsewhere (`kill`, a closed terminal) still ends the process without the
//! guard; the shell's own `reset` or `stty sane` puts echo back then.
#![allow(unsafe_code)]

use zeroize::Zeroizing;

use crate::console_keys::{Line, Step};

/// Puts the terminal's settings back however the read ends.
struct Restore(libc::termios);

impl Drop for Restore {
    fn drop(&mut self) {
        // SAFETY: fd 0 is this process's standard input; the settings are the ones tcgetattr returned for it.
        let _ = unsafe { libc::tcsetattr(0, libc::TCSAFLUSH, &raw const self.0) };
    }
}

/// Longest line read, in bytes: far past any master password, short of an unbounded paste.
const MAX_LINE: usize = 4096;

pub(crate) fn read_hidden_line() -> std::io::Result<Zeroizing<String>> {
    // SAFETY: termios is plain old data; an all-zero value is a valid out-parameter for tcgetattr.
    let mut saved: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: fd 0 and a live out-parameter; a non-terminal makes the call fail.
    if unsafe { libc::tcgetattr(0, &raw mut saved) } != 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "standard input is not a terminal"));
    }
    let restore = Restore(saved);
    let mut hidden = saved;
    hidden.c_lflag &= !(libc::ECHO | libc::ECHONL | libc::ICANON | libc::ISIG | libc::IEXTEN);
    hidden.c_cc[libc::VMIN] = 1;
    hidden.c_cc[libc::VTIME] = 0;
    // SAFETY: fd 0 is the terminal tcgetattr just read; `restore` puts the old settings back on every path.
    if unsafe { libc::tcsetattr(0, libc::TCSAFLUSH, &raw const hidden) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut line: Line<u8> = Line::new(MAX_LINE);
    let mut byte = Zeroizing::new([0u8; 1]);
    loop {
        // SAFETY: reads at most one byte into a live one-byte buffer.
        let n = unsafe { libc::read(0, byte.as_mut_ptr().cast::<libc::c_void>(), 1) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if n == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }
        match line.feed(byte[0]) {
            Step::More => {}
            Step::Done => break,
            Step::Cancelled => return Err(crate::console::cancelled()),
            Step::Ended => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
            Step::TooLong => return Err(std::io::Error::other("input line too long")),
        }
    }
    drop(restore);
    let text =
        std::str::from_utf8(line.units()).map_err(|_| std::io::Error::other("input is not valid text"))?;
    Ok(Zeroizing::new(text.to_owned()))
}
