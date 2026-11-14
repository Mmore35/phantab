//! One line typed at the owner's own terminal with echo off: how `phantab bitwarden connect` takes a
//! master password (THREAT-MODEL SR-63). Refuses when standard input is not an interactive console, so a
//! pipe, a file or an agent's shell never feeds it.

use zeroize::Zeroizing;

/// Reads one line from the console on standard input without echoing it. The line ending is not included.
/// The terminal's own line editing and its Ctrl+C signal are off for the read and restored after it on
/// every return; Backspace and Ctrl+U edit (and Esc on Windows), Ctrl+C cancels, and arrow keys are
/// skipped.
///
/// # Errors
/// Standard input is not a terminal (`ErrorKind::Unsupported`), Ctrl+C ([`is_cancelled`]), end of input
/// (`UnexpectedEof`, also Ctrl+D or Ctrl+Z on an empty line), an over-long line, or a console error. On Windows a mintty window (Git Bash) is not a console: run it in Windows Terminal,
/// PowerShell or cmd.
pub fn read_hidden_line() -> std::io::Result<Zeroizing<String>> {
    #[cfg(windows)]
    {
        crate::secret_win32::read_hidden_line()
    }
    #[cfg(unix)]
    {
        crate::console_unix::read_hidden_line()
    }
    #[cfg(not(any(windows, unix)))]
    {
        Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "no hidden console input on this platform"))
    }
}

/// The error [`read_hidden_line`] returns for Ctrl+C.
#[cfg(any(windows, unix))]
pub(crate) fn cancelled() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Interrupted, "cancelled")
}

/// Whether a [`read_hidden_line`] error is the owner pressing Ctrl+C (the CLI then exits 130, as a shell
/// does for an interrupted command).
#[must_use]
pub fn is_cancelled(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::Interrupted
}
