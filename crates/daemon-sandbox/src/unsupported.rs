//! The backend for every target other than Linux: each operation fails closed
//! with [`SandboxError::Unsupported`] and changes nothing.
//!
//! Compiled on non-Linux targets as the backend, and in tests on every target
//! so CI (Linux) also exercises it.
// Spec: docs/50 R50-14 (hardening is defined on the Linux rustix API only);
// docs/03 principles (fail closed); task P3 ("never silently succeeds").

use crate::error::SandboxError;
use crate::plan::{HardeningPlan, Step};
use crate::state::SandboxState;
use crate::StepOutcome;

/// Refuse `step`.
pub(crate) fn apply_step(step: Step, _plan: &HardeningPlan) -> Result<StepOutcome, SandboxError> {
    Err(SandboxError::Unsupported { step })
}

/// Refuse the read-back.
pub(crate) fn read_state() -> Result<SandboxState, SandboxError> {
    Err(SandboxError::Unsupported {
        step: Step::VerifyState,
    })
}

#[cfg(test)]
mod tests {
    //! Source: task P3 / docs/50 R50-14 — on a non-Linux target every
    //! hardening call returns `Unsupported` and never succeeds silently.

    use super::*;
    use crate::plan::ProcessIdentity;

    #[test]
    fn every_step_is_refused() {
        let identity = match ProcessIdentity::new(4001, 4002) {
            Ok(id) => id,
            Err(e) => panic!("valid identity refused: {e}"),
        };
        let plan = match HardeningPlan::daemon_baseline(identity)
            .open_files_limit(64)
            .locked_memory_limit(1 << 20)
            .lock_all_memory()
            .change_root("/jail")
            .build()
        {
            Ok(plan) => plan,
            Err(e) => panic!("valid plan refused: {e}"),
        };
        for step in Step::ORDER {
            assert_eq!(
                apply_step(step, &plan),
                Err(SandboxError::Unsupported { step })
            );
        }
    }

    #[test]
    fn read_back_is_refused() {
        assert_eq!(
            read_state(),
            Err(SandboxError::Unsupported {
                step: Step::VerifyState
            })
        );
    }
}
