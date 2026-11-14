//! The production [`Terminal`]: the process's standard input, when it
//! refers to a terminal, with echo turned off for each entry through
//! rustix's termios API — safe functions only, no `unsafe` in this project
//! (task A6 / P-2: "use only the API docs of rustix on docs.rs").
//!
//! # One hidden entry
//!
//! 1. the prompt goes to standard error (fixed text);
//! 2. `tcgetattr(stdin)` — the terminal's attributes now ("Get terminal
//!    attributes"), kept as the mode to restore;
//! 3. `tcsetattr(stdin, OptionalActions::Flush, hidden)` ("Discard any
//!    pending input and then make the change after all output has been
//!    transmitted" — the prompt is out, and nothing typed before it is taken
//!    as the password), where `hidden` is the saved `Termios` with the
//!    `LocalModes` flags **`ECHO`** and **`ISIG`** removed;
//! 4. one line is read from a duplicate of standard input's descriptor
//!    with std's unbuffered `Read::read` into a zeroizing buffer, at most
//!    1024 octets kept (an overlong line is read on to its end and
//!    discarded, so no part of it is left for the shell);
//! 5. the saved mode is set back, again with `Flush`, and a newline goes to
//!    standard error (the one typed was not echoed).
//!
//! **Restored on every exit path:** step 5 runs whatever step 3 or 4
//! returned, and a guard runs it on unwinding too. `ISIG` is removed so
//! that the interrupt and suspend keys do not end or stop the process
//! between steps 3 and 5 — they arrive as control characters, which the line
//! rule refuses (module `line`), and the entry ends through step 5. A
//! signal sent from outside the terminal (or a hang-up) still ends the
//! process without step 5: handling it needs a signal handler, which is
//! not reachable without `unsafe` or a new dependency — a documented
//! residual (docs/questions/Q-412). The meaning of the two flags rests on
//! their names: the rustix pages document `ECHO` and `ISIG` by name only
//! and refer to the operating system's manual pages, which are not an
//! allowed source (P-18) — Q-412.
//!
//! Not driven in CI: a real terminal cannot be attached to a test run. The
//! restore logic is generic over [`ModeControl`] and unit-tested with an
//! injected mode store and reader on every exit path; the rustix layer is
//! three calls.
//!
//! Spec: docs/51 §4.4 (source (a)); task A6 ("restore the terminal mode on
//! every exit path"); rustix 1.1.6 docs.rs (P-2): `termios` (crate feature
//! `termios`), `termios::isatty` ("Tests whether a file descriptor refers to
//! a terminal"), `termios::tcgetattr`, `termios::tcsetattr`,
//! `termios::OptionalActions::Flush`, `termios::Termios` (`local_modes`,
//! `Clone`), `termios::LocalModes::{ECHO, ISIG}`, `remove`; std API
//! documentation: `io::Stdin` (`AsFd`), `os::fd::BorrowedFd::
//! try_clone_to_owned`, `fs::File: From<OwnedFd>`, `io::Read::read`
//! (`Ok(0)`: end of file; `ErrorKind::Interrupted`); docs/questions/Q-412.

use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::os::fd::{AsFd, BorrowedFd};

use rustix::termios::{LocalModes, OptionalActions, Termios};
use zeroize::{Zeroize, Zeroizing};

use super::entry::{EntryError, Terminal};
use super::line::{LF, MAX_PASSWORD_OCTETS};

/// Octets read per call. Project choice.
const CHUNK: usize = 256;

/// The most octets read on, and discarded, after an overlong line before
/// the entry gives up looking for its end. Project choice (bounded,
/// AGENTS.md §6).
const DISCARD_LIMIT: usize = 1024 * 1024;

/// Getting and setting a terminal's mode (the seam of the restore logic).
pub trait ModeControl {
    /// A terminal mode.
    type Mode;

    /// The mode now.
    ///
    /// # Errors
    /// [`EntryError::Terminal`].
    fn current(&mut self) -> Result<Self::Mode, EntryError>;

    /// Set `mode`.
    ///
    /// # Errors
    /// [`EntryError::Terminal`].
    fn apply(&mut self, mode: &Self::Mode) -> Result<(), EntryError>;

    /// `mode` with echo and the signal keys off.
    fn hidden(mode: &Self::Mode) -> Self::Mode;
}

/// Sets the saved mode back when dropped, unless [`Restore::finish`] did.
struct Restore<'a, M: ModeControl> {
    modes: &'a mut M,
    saved: M::Mode,
    done: bool,
}

impl<M: ModeControl> Restore<'_, M> {
    /// Set the saved mode back now and say whether that worked.
    fn finish(mut self) -> Result<(), EntryError> {
        self.done = true;
        self.modes
            .apply(&self.saved)
            .map_err(|_| EntryError::NotRestored)
    }
}

impl<M: ModeControl> Drop for Restore<'_, M> {
    fn drop(&mut self) {
        if !self.done {
            // Unwinding (or an early return): restore, best effort.
            let _ = self.modes.apply(&self.saved);
        }
    }
}

/// One hidden entry over `modes` and `input` (module documentation, steps
/// 2-5 without the prompt): the line, without its LF, in `line`. On any
/// error `line` is wiped.
///
/// # Errors
/// [`EntryError`]; [`EntryError::NotRestored`] wins over the read's own
/// result when the mode could not be set back.
///
/// Spec: module documentation.
pub fn hidden_line<M: ModeControl, R: Read>(
    modes: &mut M,
    input: &mut R,
    line: &mut Zeroizing<Vec<u8>>,
) -> Result<(), EntryError> {
    line.zeroize();
    // Empty now: growing it moves no octet of a password.
    line.reserve(MAX_PASSWORD_OCTETS);
    let saved = modes.current()?;
    let hidden = M::hidden(&saved);
    let guard = Restore {
        modes,
        saved,
        done: false,
    };
    let entered = match guard.modes.apply(&hidden) {
        Ok(()) => read_line(input, line),
        Err(e) => Err(e),
    };
    let restored = guard.finish();
    let result = restored.and(entered);
    if result.is_err() {
        line.zeroize();
    }
    result
}

/// Read one line (module documentation, step 4).
fn read_line<R: Read>(input: &mut R, line: &mut Zeroizing<Vec<u8>>) -> Result<(), EntryError> {
    let mut chunk = Zeroizing::new([0u8; CHUNK]);
    loop {
        let n = match input.read(&mut chunk[..]) {
            Ok(0) => return Err(EntryError::EndOfInput),
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return Err(EntryError::Terminal),
        };
        let got = &chunk[..n];
        match got.iter().position(|&b| b == LF) {
            Some(end) => {
                if end + 1 != n {
                    return Err(EntryError::NotOneLine);
                }
                if line.len() + end > MAX_PASSWORD_OCTETS {
                    return Err(EntryError::TooLong);
                }
                line.extend_from_slice(&got[..end]);
                return Ok(());
            }
            None => {
                if line.len() + n > MAX_PASSWORD_OCTETS {
                    discard_rest_of_line(input, &mut chunk);
                    return Err(EntryError::TooLong);
                }
                line.extend_from_slice(got);
            }
        }
    }
}

/// Read on, discarding, to the end of the current line (or of the input,
/// or [`DISCARD_LIMIT`] octets).
fn discard_rest_of_line<R: Read>(input: &mut R, chunk: &mut Zeroizing<[u8; CHUNK]>) {
    let mut discarded = 0;
    while discarded < DISCARD_LIMIT {
        match input.read(&mut chunk[..]) {
            Ok(0) => return,
            Ok(n) => {
                if chunk[..n].contains(&LF) {
                    return;
                }
                discarded += n;
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return,
        }
    }
}

/// The termios mode of standard input (rustix).
struct TermiosModes<'fd> {
    fd: BorrowedFd<'fd>,
}

impl ModeControl for TermiosModes<'_> {
    type Mode = Termios;

    /// Spec: rustix `termios::tcgetattr`.
    fn current(&mut self) -> Result<Termios, EntryError> {
        rustix::termios::tcgetattr(self.fd).map_err(|_| EntryError::Terminal)
    }

    /// Spec: rustix `termios::tcsetattr`, `OptionalActions::Flush`.
    fn apply(&mut self, mode: &Termios) -> Result<(), EntryError> {
        rustix::termios::tcsetattr(self.fd, OptionalActions::Flush, mode)
            .map_err(|_| EntryError::Terminal)
    }

    /// Spec: rustix `Termios::local_modes`, `LocalModes::{ECHO, ISIG}`,
    /// `remove`; module documentation (Q-412).
    fn hidden(mode: &Termios) -> Termios {
        let mut hidden = mode.clone();
        hidden
            .local_modes
            .remove(LocalModes::ECHO | LocalModes::ISIG);
        hidden
    }
}

/// Standard input as the terminal to enter passwords at; prompts on
/// standard error.
#[derive(Debug, Default)]
pub struct StdinTerminal {
    _private: (),
}

impl StdinTerminal {
    /// The process's standard input.
    #[must_use]
    pub fn new() -> StdinTerminal {
        StdinTerminal { _private: () }
    }
}

impl Terminal for StdinTerminal {
    /// Spec: rustix `termios::isatty`.
    fn is_terminal(&self) -> bool {
        rustix::termios::isatty(std::io::stdin().as_fd())
    }

    /// Spec: module documentation.
    fn read_hidden(
        &mut self,
        prompt: &str,
        line: &mut Zeroizing<Vec<u8>>,
    ) -> Result<(), EntryError> {
        let stdin = std::io::stdin();
        let fd = stdin.as_fd();
        let mut input = File::from(fd.try_clone_to_owned().map_err(|_| EntryError::Terminal)?);
        {
            let mut err = std::io::stderr().lock();
            let _ = err.write_all(prompt.as_bytes());
            let _ = err.flush();
        }
        let mut modes = TermiosModes { fd };
        let result = hidden_line(&mut modes, &mut input, line);
        let _ = writeln!(std::io::stderr().lock());
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// What the fake mode store saw.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Seen {
        Get,
        Set(u32),
    }

    const ECHO_BIT: u32 = 0b01;
    const SIGNAL_BIT: u32 = 0b10;
    const SAVED: u32 = 0b111;

    /// A mode store: modes are bits; `hidden` clears the echo and signal
    /// bits; any step may be made to fail.
    struct FakeModes {
        mode: u32,
        log: Rc<RefCell<Vec<Seen>>>,
        fail_get: bool,
        fail_hide: bool,
        fail_restore: bool,
    }

    impl FakeModes {
        fn new() -> FakeModes {
            FakeModes {
                mode: SAVED,
                log: Rc::new(RefCell::new(Vec::new())),
                fail_get: false,
                fail_hide: false,
                fail_restore: false,
            }
        }
    }

    impl ModeControl for FakeModes {
        type Mode = u32;

        fn current(&mut self) -> Result<u32, EntryError> {
            self.log.borrow_mut().push(Seen::Get);
            if self.fail_get {
                return Err(EntryError::Terminal);
            }
            Ok(self.mode)
        }

        fn apply(&mut self, mode: &u32) -> Result<(), EntryError> {
            self.log.borrow_mut().push(Seen::Set(*mode));
            let restoring = *mode == SAVED;
            if (restoring && self.fail_restore) || (!restoring && self.fail_hide) {
                return Err(EntryError::Terminal);
            }
            self.mode = *mode;
            Ok(())
        }

        fn hidden(mode: &u32) -> u32 {
            mode & !(ECHO_BIT | SIGNAL_BIT)
        }
    }

    /// The hidden mode was set, then the saved one.
    fn hid_then_restored(log: &[Seen]) -> bool {
        log == [Seen::Get, Seen::Set(0b100), Seen::Set(SAVED)]
    }

    /// A reader that fails.
    struct Failing;

    impl Read for Failing {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("test"))
        }
    }

    /// A reader that panics.
    struct Panicking;

    impl Read for Panicking {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            panic!("test reader panics");
        }
    }

    /// A reader that delivers one octet per call.
    struct Trickle<'a>(&'a [u8]);

    impl Read for Trickle<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            match self.0.split_first() {
                Some((first, rest)) if !buf.is_empty() => {
                    buf[0] = *first;
                    self.0 = rest;
                    Ok(1)
                }
                _ => Ok(0),
            }
        }
    }

    /// Task A6: the line is read with echo and the signal keys off, and the
    /// saved mode is back afterwards.
    #[test]
    fn a_line_is_read_hidden_and_the_mode_restored() {
        let mut modes = FakeModes::new();
        let mut line = Zeroizing::new(Vec::new());
        let mut input: &[u8] = b"Juniper-Kettle-71\n";
        hidden_line(&mut modes, &mut input, &mut line).unwrap();
        assert_eq!(line.as_slice(), b"Juniper-Kettle-71");
        assert!(hid_then_restored(&modes.log.borrow()));
        assert_eq!(modes.mode, SAVED);
        let mut line = Zeroizing::new(Vec::new());
        hidden_line(&mut FakeModes::new(), &mut Trickle(b"abc\n"), &mut line).unwrap();
        assert_eq!(line.as_slice(), b"abc");
    }

    /// Task A6 ("restore the terminal mode on every exit path"): end of
    /// input, a read error, an overlong line, two lines at once — each
    /// restores the saved mode and leaves no octet in the buffer.
    #[test]
    fn every_failed_read_restores_the_mode() {
        let long = [b'a'; 2000];
        let mut overlong = long.to_vec();
        overlong.push(LF);
        overlong.extend_from_slice(b"next\n");
        let cases: Vec<(Box<dyn Read>, EntryError)> = vec![
            (Box::new(&b"no-terminator"[..]), EntryError::EndOfInput),
            (Box::new(&b""[..]), EntryError::EndOfInput),
            (Box::new(Failing), EntryError::Terminal),
            (
                Box::new(std::io::Cursor::new(overlong)),
                EntryError::TooLong,
            ),
            (Box::new(&b"one\ntwo\n"[..]), EntryError::NotOneLine),
        ];
        for (mut input, expected) in cases {
            let mut modes = FakeModes::new();
            let mut line = Zeroizing::new(Vec::new());
            assert_eq!(
                hidden_line(&mut modes, &mut input, &mut line),
                Err(expected)
            );
            assert!(hid_then_restored(&modes.log.borrow()), "{expected:?}");
            assert!(line.is_empty());
        }
        // 1024 octets fit; 1025 do not.
        let mut line = Zeroizing::new(Vec::new());
        let mut ok = vec![b'a'; MAX_PASSWORD_OCTETS];
        ok.push(LF);
        hidden_line(&mut FakeModes::new(), &mut &ok[..], &mut line).unwrap();
        assert_eq!(line.len(), MAX_PASSWORD_OCTETS);
        let mut over = vec![b'a'; MAX_PASSWORD_OCTETS + 1];
        over.push(LF);
        assert_eq!(
            hidden_line(&mut FakeModes::new(), &mut &over[..], &mut line),
            Err(EntryError::TooLong)
        );
    }

    /// The rest of an overlong line is read and discarded: what follows its
    /// end is still there for whoever reads next.
    #[test]
    fn an_overlong_line_is_consumed_to_its_end() {
        let mut data = vec![b'a'; 3000];
        data.push(LF);
        data.extend_from_slice(b"next\n");
        let mut input = Trickle(&data);
        let mut line = Zeroizing::new(Vec::new());
        assert_eq!(
            hidden_line(&mut FakeModes::new(), &mut input, &mut line),
            Err(EntryError::TooLong)
        );
        assert_eq!(input.0, b"next\n");
    }

    /// The mode store failing: no mode to restore when it cannot be read;
    /// a failed hide is still followed by a restore; a failed restore is
    /// reported (and wins over a successful read).
    #[test]
    fn mode_store_failures() {
        let mut modes = FakeModes::new();
        modes.fail_get = true;
        let mut line = Zeroizing::new(Vec::new());
        assert_eq!(
            hidden_line(&mut modes, &mut &b"x\n"[..], &mut line),
            Err(EntryError::Terminal)
        );
        assert_eq!(*modes.log.borrow(), [Seen::Get]);

        let mut modes = FakeModes::new();
        modes.fail_hide = true;
        assert_eq!(
            hidden_line(&mut modes, &mut &b"x\n"[..], &mut line),
            Err(EntryError::Terminal)
        );
        assert!(hid_then_restored(&modes.log.borrow()));

        let mut modes = FakeModes::new();
        modes.fail_restore = true;
        assert_eq!(
            hidden_line(&mut modes, &mut &b"Juniper-Kettle-71\n"[..], &mut line),
            Err(EntryError::NotRestored)
        );
        assert!(line.is_empty());
    }

    /// A panic while reading still restores the mode (the guard, on
    /// unwinding).
    #[test]
    fn a_panic_restores_the_mode() {
        let mut modes = FakeModes::new();
        let log = Rc::clone(&modes.log);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut line = Zeroizing::new(Vec::new());
            let _ = hidden_line(&mut modes, &mut Panicking, &mut line);
        }));
        assert!(outcome.is_err());
        assert!(hid_then_restored(&log.borrow()));
    }

    /// With a real terminal on standard input (never in CI), the hidden mode
    /// has neither ECHO nor ISIG and keeps every other local flag; the
    /// terminal itself is not changed by this test.
    #[test]
    fn the_hidden_termios_mode() {
        let stdin = std::io::stdin();
        let Ok(saved) = rustix::termios::tcgetattr(stdin.as_fd()) else {
            eprintln!("skipped: standard input is not a terminal (task A6: a real TTY cannot be driven in CI)");
            return;
        };
        let hidden = TermiosModes::hidden(&saved);
        assert!(!hidden.local_modes.contains(LocalModes::ECHO));
        assert!(!hidden.local_modes.contains(LocalModes::ISIG));
        let mut expected = saved.local_modes;
        expected.remove(LocalModes::ECHO | LocalModes::ISIG);
        assert_eq!(hidden.local_modes, expected);
    }
}
