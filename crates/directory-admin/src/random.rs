//! Randomness for objectGUIDs.
//!
//! This crate implements no random number generator (AGENTS.md §6 "never
//! implement ... RNG") and links no randomness crate. The production source
//! is [`OsRandom`]: the operating-system kernel CSPRNG read through
//! `/dev/urandom` with `read_exact`, the same source keyd uses (A-15, as
//! decided for provisioning in A-77). Any failure — the device cannot be
//! opened, is not a character device, or returns a short read — is an
//! error, and the write fails closed. There is no fallback.
//!
//! The [`RandomSource`] trait exists so that tests can inject a
//! deterministic source; only [`OsRandom`] may be used outside tests.
//!
//! Spec: [MS-ADTS] 3.1.1.5.2.4 ("For originating updates, a new objectGUID
//! value is generated and set on the object. This value MUST NOT be the
//! NULL GUID"); docs/51 R51-3, R51-17 (every identifier from the CSPRNG;
//! dird, not admind, draws it); A-15; A-77; AGENTS.md §6.

/// The random source failed. Carries no data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RandomError;

/// A source of cryptographically strong random octets.
/// Spec: docs/51 R51-3; A-15.
pub trait RandomSource {
    /// Fill `out` completely with random octets, or fail. A partial fill
    /// must be reported as an error.
    fn fill(&mut self, out: &mut [u8]) -> Result<(), RandomError>;
}

/// The kernel CSPRNG via `/dev/urandom` — the only source permitted outside
/// tests. Fails closed on any error. Spec: A-15; AGENTS.md §6.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsRandom {
    _private: (),
}

impl OsRandom {
    /// The OS source.
    #[must_use]
    pub const fn new() -> OsRandom {
        OsRandom { _private: () }
    }
}

/// The device path of the kernel CSPRNG (A-15).
#[cfg(unix)]
const URANDOM_PATH: &str = "/dev/urandom";

impl RandomSource for OsRandom {
    #[cfg(unix)]
    fn fill(&mut self, out: &mut [u8]) -> Result<(), RandomError> {
        use std::io::Read;
        use std::os::unix::fs::FileTypeExt;

        if out.is_empty() {
            return Ok(());
        }
        let mut device = std::fs::File::open(URANDOM_PATH).map_err(|_| RandomError)?;
        // Anything that is not a character device (e.g. a regular file
        // planted at the path) is refused — fail closed.
        let metadata = device.metadata().map_err(|_| RandomError)?;
        if !metadata.file_type().is_char_device() {
            return Err(RandomError);
        }
        device.read_exact(out).map_err(|_| RandomError)
    }

    /// No kernel CSPRNG path is defined for this platform: always fail
    /// closed rather than use anything weaker.
    #[cfg(not(unix))]
    fn fill(&mut self, _out: &mut [u8]) -> Result<(), RandomError> {
        Err(RandomError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The OS source fills the whole buffer, and two draws differ (smoke
    /// test on the build host; AGENTS.md §6).
    #[test]
    #[cfg(unix)]
    fn os_random_fills_the_buffer() {
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        OsRandom::new().fill(&mut a).unwrap();
        OsRandom::new().fill(&mut b).unwrap();
        assert_ne!(a, b);
    }
}
