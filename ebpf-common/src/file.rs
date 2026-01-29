use crate::{Action, FileOp};
#[cfg(feature = "user")]
use serde::{Deserialize, Serialize};

/// High-level file access rule description with operation-specific control.
///
/// Note: actual eBPF side should avoid variable-length data; any strings
/// here are for user-space configuration and must be converted into
/// fixed-size keys/values before being pushed to BPF maps.
#[cfg(feature = "user")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRule {
    pub path_prefix: String,
    pub operations: Vec<FileOp>, // Which operations to control
    pub action: Action,
    pub mode: Option<crate::Mode>, // Individual rule mode override
}
