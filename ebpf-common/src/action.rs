#[cfg(feature = "user")]
use serde::{Deserialize, Serialize};

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(Serialize, Deserialize))]
pub enum Action {
    Allow = 0,
    Deny = 1,
    Redirect = 2,
}

/// Operating mode: Monitor (log only) or Protect (block + log)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(Serialize, Deserialize))]
pub enum Mode {
    Monitor = 0, // Only log, don't block
    Protect = 1, // Block denied actions and log
}

/// File operation types for fine-grained control
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(Serialize, Deserialize))]
pub enum FileOp {
    Read = 0,
    Write = 1,
    Create = 2,
    Delete = 3,
    Execute = 4,
}
