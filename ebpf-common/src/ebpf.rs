//! eBPF-side data structures used by eBPF programs
//!
//! These structs match the C structs used in eBPF code

/// Maximum length for command names
pub const MAX_COMM_LEN: usize = 16;

/// Maximum length for paths
pub const MAX_PATH_LEN: usize = 256;

/// File operation types
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileOpType {
    Open = 0,
    Create = 1,
    Delete = 2,
    Rename = 3,
}

/// File event structure for ring buffer
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FileEvent {
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub gid: u32,
    pub timestamp_ns: u64,
    pub comm: [u8; MAX_COMM_LEN],
    pub path: [u8; MAX_PATH_LEN],
    pub op_type: FileOpType,
    pub blocked: u8,
}

/// Global configuration for eBPF programs
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct GlobalConfig {
    pub file_enabled: u8,
    pub process_enabled: u8,
    pub network_enabled: u8,
}
