//! Randomness for session keys, long-term keys, confounders and one-time
//! token ids.
//!
//! keyd implements no random number generator (AGENTS.md §6 "never implement
//! ... RNG") and links no randomness crate. The only production source is
//! [`OsEntropy`]: the operating-system kernel CSPRNG read through
//! `/dev/urandom` with `read_exact`. Any failure — the device cannot be
//! opened, is not a character device, or returns a short read — is an error,
//! and keyd fails the operation closed. There is no fallback to anything
//! weaker.
//!
//! The [`EntropySource`] trait exists so that tests can inject a
//! deterministic source. ONLY [`OsEntropy`] is used outside tests:
//! `Keyd::new` always uses it, and the injecting constructor
//! `Keyd::with_entropy` exists only with the feature `test-seams`, which
//! only `[dev-dependencies]` enable — a product build has no way to give
//! keyd another source (docs/52 C18; docs/questions/Q-843 item 2).
//!
//! Residual: the quality of `/dev/urandom` early in boot (before the kernel
//! pool is initialized) is the platform's responsibility; the keyd daemon
//! must start after the system has initialized its entropy.
//!
//! Spec: RFC 4120 3.1.3 (the session key must be unguessable; "See
//! [RFC4086]"); RFC 3961 §3 (random-to-key takes a random bitstring, "a
//! confounder should be included"); AGENTS.md §6.

/// Entropy failure. Carries no data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntropyError;

/// A source of cryptographically strong random octets.
///
/// Spec: RFC 4120 3.1.3; RFC 3961 §3.
pub trait EntropySource {
    /// Fill `out` completely with random octets, or fail. A partial fill
    /// must be reported as an error.
    fn fill(&mut self, out: &mut [u8]) -> Result<(), EntropyError>;
}

/// The kernel CSPRNG via `/dev/urandom` — the only source permitted outside
/// tests. Fails closed on any error.
///
/// Spec: AGENTS.md §6; RFC 4120 3.1.3.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsEntropy {
    _private: (),
}

impl OsEntropy {
    /// The OS source. Spec: AGENTS.md §6.
    pub const fn new() -> Self {
        OsEntropy { _private: () }
    }
}

/// The device path of the kernel CSPRNG.
#[cfg(unix)]
const URANDOM_PATH: &str = "/dev/urandom";

impl EntropySource for OsEntropy {
    #[cfg(unix)]
    fn fill(&mut self, out: &mut [u8]) -> Result<(), EntropyError> {
        use std::io::Read;
        use std::os::unix::fs::FileTypeExt;

        if out.is_empty() {
            return Ok(());
        }
        let mut device = std::fs::File::open(URANDOM_PATH).map_err(|_| EntropyError)?;
        // Refuse anything that is not a character device (e.g. a regular file
        // planted at the path inside a chroot) — fail closed.
        let metadata = device.metadata().map_err(|_| EntropyError)?;
        if !metadata.file_type().is_char_device() {
            return Err(EntropyError);
        }
        device.read_exact(out).map_err(|_| EntropyError)
    }

    /// No kernel CSPRNG path is defined for this platform: always fail
    /// closed rather than use anything weaker.
    #[cfg(not(unix))]
    fn fill(&mut self, _out: &mut [u8]) -> Result<(), EntropyError> {
        Err(EntropyError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The OS source fills the whole buffer (smoke test on the build host).
    #[test]
    #[cfg(unix)]
    fn os_entropy_fills_buffer() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        OsEntropy::new().fill(&mut a).unwrap();
        OsEntropy::new().fill(&mut b).unwrap();
        // Two 256-bit draws are equal with negligible probability.
        assert_ne!(a, b);
        assert!(OsEntropy::new().fill(&mut []).is_ok());
    }
}
