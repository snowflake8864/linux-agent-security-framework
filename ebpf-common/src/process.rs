use crate::Action;
#[cfg(feature = "user")]
use serde::{Deserialize, Serialize};

/// High-level process control rule description.
#[cfg(feature = "user")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessRule {
    /// Command name (comm) to match, e.g. "bash".
    pub comm: String,
    pub action: Action,
    pub mode: Option<crate::Mode>, // Individual rule mode override
}
