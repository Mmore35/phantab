//! The keys of a hidden prompt, as pure logic over what the console sends (THREAT-MODEL SR-63), so it is
//! tested without a terminal. The OS halves ([`crate::console_unix`], [`crate::secret_win32`]) turn the
//! terminal's own line editing and signal keys off and feed every unit here:
//!
//! | Key                          | Unit                                | Effect                                   |
//! |------------------------------|-------------------------------------|------------------------------------------|
//! | Enter                        | CR or LF (0x0D, 0x0A)               | the line is done                         |
//! | Ctrl+C                       | 0x03                                | cancelled (the CLI exits 130)            |
//! | Ctrl+D, Ctrl+Z               | 0x04, 0x1A                          | end of input on an empty line, else none |
//! | Backspace                    | 0x08 or 0x7F                        | erases the last character                |
//! | Ctrl+U                       | 0x15                                | erases the whole line                    |
//! | arrows, function keys (Unix) | `ESC [` or `ESC O` ... 0x40-0x7E    | skipped                                  |
//! | Esc (Windows)                | 0x1B                                | erases the whole line, as cmd does       |
//! | any other control character  | 0x00-0x1F                           | ignored                                  |
//!
//! A key from the rows above Esc counts even inside an unfinished escape sequence, which it abandons: a
//! cut-off sequence never swallows Ctrl+C or Enter. Windows reads with virtual-terminal input off, so
//! its arrow keys send nothing and Esc is a key of its own, not the start of a sequence.
//!
//! A unit is a UTF-8 byte (Unix) or a UTF-16 unit (Windows); erasing takes off a whole character (the
//! continuation bytes of UTF-8, the low half of a surrogate pair, then the unit that starts it).

use zeroize::{Zeroize, Zeroizing};

/// One unit of console input: a byte of UTF-8 or a unit of UTF-16.
pub(crate) trait Unit: Copy + Default + Zeroize {
    /// The unit's numeric value.
    fn value(self) -> u32;
    /// Whether the unit continues a character begun by an earlier unit.
    fn continues(self) -> bool;
    /// Whether ESC starts an escape sequence (a Unix terminal) rather than being the Esc key (a Windows
    /// console with virtual-terminal input off).
    const ESCAPE_SEQUENCES: bool;
}

impl Unit for u8 {
    const ESCAPE_SEQUENCES: bool = true;
    fn value(self) -> u32 {
        u32::from(self)
    }
    fn continues(self) -> bool {
        self & 0xC0 == 0x80
    }
}

impl Unit for u16 {
    const ESCAPE_SEQUENCES: bool = false;
    fn value(self) -> u32 {
        u32::from(self)
    }
    fn continues(self) -> bool {
        (0xDC00..=0xDFFF).contains(&self)
    }
}

/// What one unit did to the line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Step {
    /// Keep reading.
    More,
    /// Enter: the line is complete.
    Done,
    /// Ctrl+C.
    Cancelled,
    /// End of input on an empty line.
    Ended,
    /// The line would pass its limit.
    TooLong,
}

/// Where the reader is in an escape sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Escape {
    None,
    /// After ESC.
    Started,
    /// After `ESC [` or `ESC O`, until a final unit (0x40-0x7E).
    Sequence,
}

/// The keys that count even inside an unfinished escape sequence: Enter, Ctrl+C, Ctrl+D and Ctrl+Z,
/// Backspace, Ctrl+U.
fn acts(v: u32) -> bool {
    matches!(v, 0x0D | 0x0A | 0x03 | 0x04 | 0x1A | 0x08 | 0x7F | 0x15)
}

/// The line being typed, wiped from memory when dropped.
pub(crate) struct Line<U: Unit> {
    units: Zeroizing<Vec<U>>,
    max: usize,
    escape: Escape,
}

impl<U: Unit> Line<U> {
    /// An empty line that holds at most `max` units.
    pub(crate) fn new(max: usize) -> Self {
        Self { units: Zeroizing::new(Vec::with_capacity(max)), max, escape: Escape::None }
    }

    /// The units typed so far, without the line ending.
    pub(crate) fn units(&self) -> &[U] {
        &self.units
    }

    /// Takes one unit of input.
    pub(crate) fn feed(&mut self, unit: U) -> Step {
        let v = unit.value();
        match self.escape {
            Escape::Started => {
                self.escape = Escape::None;
                if v == u32::from(b'[') || v == u32::from(b'O') {
                    self.escape = Escape::Sequence;
                    return Step::More;
                }
                // ESC and an ordinary key (Alt+key): the ESC is dropped, the key counts.
            }
            Escape::Sequence if acts(v) => self.escape = Escape::None,
            Escape::Sequence => {
                if (0x40..=0x7E).contains(&v) {
                    self.escape = Escape::None;
                }
                return Step::More;
            }
            Escape::None => {}
        }
        match v {
            0x0D | 0x0A => Step::Done,
            0x03 => Step::Cancelled,
            0x04 | 0x1A if self.units.is_empty() => Step::Ended,
            0x08 | 0x7F => {
                self.erase();
                Step::More
            }
            0x1B if U::ESCAPE_SEQUENCES => {
                self.escape = Escape::Started;
                Step::More
            }
            // Ctrl+U, and Esc on a Windows console.
            0x15 | 0x1B => {
                self.units.zeroize();
                Step::More
            }
            0x00..=0x1F => Step::More,
            _ if self.units.len() >= self.max => Step::TooLong,
            _ => {
                self.units.push(unit);
                Step::More
            }
        }
    }

    /// Takes off the last character.
    fn erase(&mut self) {
        while self.units.last().is_some_and(|u| u.continues()) {
            self.units.pop();
        }
        self.units.pop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feeds `input` until a step other than `More`; returns that step (or `More` at the end) and the line.
    fn typed<U: Unit>(input: &[U], max: usize) -> (Step, Vec<U>) {
        let mut line = Line::new(max);
        for &u in input {
            let step = line.feed(u);
            if step != Step::More {
                return (step, line.units().to_vec());
            }
        }
        (Step::More, line.units().to_vec())
    }

    fn bytes(input: &str) -> (Step, String) {
        let (step, units) = typed(input.as_bytes(), 64);
        (step, String::from_utf8(units).unwrap_or_else(|_| "<not utf-8>".to_owned()))
    }

    #[test]
    fn enter_ends_the_line() {
        assert_eq!(bytes("hunter2\n"), (Step::Done, "hunter2".to_owned()));
        assert_eq!(bytes("hunter2\r"), (Step::Done, "hunter2".to_owned()));
        assert_eq!(bytes("\r"), (Step::Done, String::new()));
        assert_eq!(bytes("pässwörd\n"), (Step::Done, "pässwörd".to_owned()));
        assert_eq!(bytes("no end yet"), (Step::More, "no end yet".to_owned()));
    }

    #[test]
    fn ctrl_c_cancels_anywhere() {
        assert_eq!(bytes("\x03").0, Step::Cancelled);
        assert_eq!(bytes("half\x03typed\n").0, Step::Cancelled);
        assert_eq!(bytes("\x1b[\x03").0, Step::Cancelled, "a cut-off escape sequence does not swallow it");
        assert_eq!(bytes("\x1b[1;\x03").0, Step::Cancelled);
        assert_eq!(bytes("\x1bO\x03").0, Step::Cancelled);
    }

    #[test]
    fn ctrl_d_and_ctrl_z_end_only_an_empty_line() {
        assert_eq!(bytes("\x04"), (Step::Ended, String::new()));
        assert_eq!(bytes("\x1a"), (Step::Ended, String::new()));
        assert_eq!(bytes("ab\x04c\n"), (Step::Done, "abc".to_owned()));
        assert_eq!(bytes("a\x08\x04").0, Step::Ended, "erased back to empty");
    }

    #[test]
    fn backspace_and_ctrl_u_edit() {
        assert_eq!(bytes("abc\x7fd\n"), (Step::Done, "abd".to_owned()));
        assert_eq!(bytes("abc\x08\x08\n"), (Step::Done, "a".to_owned()));
        assert_eq!(bytes("\x7f\x7fa\n"), (Step::Done, "a".to_owned()), "nothing to erase is fine");
        assert_eq!(bytes("aé\x7f\n"), (Step::Done, "a".to_owned()), "a whole UTF-8 character");
        assert_eq!(bytes("a🔑\x7f\n"), (Step::Done, "a".to_owned()));
        assert_eq!(bytes("secret\x15new\n"), (Step::Done, "new".to_owned()));
    }

    #[test]
    fn escape_sequences_and_controls_are_skipped() {
        assert_eq!(bytes("a\x1b[Db\n"), (Step::Done, "ab".to_owned()), "left arrow");
        assert_eq!(bytes("a\x1b[1;5Cb\n"), (Step::Done, "ab".to_owned()), "ctrl+right");
        assert_eq!(bytes("a\x1b[3~b\n"), (Step::Done, "ab".to_owned()), "delete");
        assert_eq!(bytes("a\x1bOPb\n"), (Step::Done, "ab".to_owned()), "F1");
        assert_eq!(bytes("a\x1bxb\n"), (Step::Done, "axb".to_owned()), "alt+x keeps the x");
        assert_eq!(bytes("a\x1b\x1b[Ab\n"), (Step::Done, "ab".to_owned()));
        // The keys that act still act inside a cut-off sequence, and end it.
        assert_eq!(bytes("ab\x1b[1\n"), (Step::Done, "ab".to_owned()), "enter");
        assert_eq!(bytes("ab\x1b[\r"), (Step::Done, "ab".to_owned()), "enter");
        assert_eq!(bytes("ab\x1b[1\x7fc\n"), (Step::Done, "ac".to_owned()), "backspace, then typing counts");
        assert_eq!(bytes("ab\x1b[\x08c\n"), (Step::Done, "ac".to_owned()));
        assert_eq!(bytes("ab\x1b[\x15c\n"), (Step::Done, "c".to_owned()), "ctrl+u");
        assert_eq!(bytes("\x1b[\x04").0, Step::Ended, "ctrl+d on an empty line");
        assert_eq!(bytes("\x1b[\x1fA\n"), (Step::Done, String::new()), "other controls stay in the sequence");
        assert_eq!(bytes("a\tb\x00\x1c\x1f\n"), (Step::Done, "ab".to_owned()));
    }

    #[test]
    fn a_line_stops_at_its_limit() {
        assert_eq!(typed(b"abcd\n", 4), (Step::Done, b"abcd".to_vec()));
        assert_eq!(typed(b"abcde\n", 4).0, Step::TooLong);
        assert_eq!(typed(b"abcd\x7fe\n", 4), (Step::Done, b"abce".to_vec()));
    }

    #[test]
    fn utf16_units_from_a_windows_console() {
        let units = |s: &str| s.encode_utf16().collect::<Vec<u16>>();
        assert_eq!(typed(&units("hunter2\r"), 64), (Step::Done, units("hunter2")));
        assert_eq!(
            typed(&units("a🔑\x08\r"), 64),
            (Step::Done, units("a")),
            "a surrogate pair is one character"
        );
        assert_eq!(typed(&units("a🔑b\x08\r"), 64), (Step::Done, units("a🔑")));
        assert_eq!(typed(&units("x\x03"), 64).0, Step::Cancelled);
        assert_eq!(typed(&units("\x1a"), 64).0, Step::Ended);
        // Esc is a key here: it erases the line, and what follows is typed as usual.
        assert_eq!(typed(&units("\x1bOrange\r"), 64), (Step::Done, units("Orange")));
        assert_eq!(typed(&units("wrong\x1b[Orange\r"), 64), (Step::Done, units("[Orange")));
        assert_eq!(typed(&units("a\x1b\x1bb\r"), 64), (Step::Done, units("b")));
    }
}
