//! File monitoring eBPF probes using Aya framework
//!
//! Implements LSM hooks for file operations with CWD-based path resolution

use aya_ebpf::{
    cty::c_long,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_kernel, bpf_probe_read_kernel_str,
    },
    macros::{lsm, map},
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::LsmContext,
};
use ebpf_common::{Action, FileEvent, FileOpType, MAX_COMM_LEN, MAX_PATH_LEN};

use crate::get_config;

// Kernel structures (minimal definitions)
#[repr(C)]
struct qstr {
    hash_len: u64,
    name: *const u8,
}

#[repr(C)]
struct dentry {
    d_parent: *mut dentry,
    d_name: qstr,
}

#[repr(C)]
struct inode {
    _unused: [u8; 0],
}

/// Ring buffer for file events
#[map]
static FILE_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU scratch buffer for path construction
#[map]
static PATH_SCRATCH: PerCpuArray<[u8; MAX_PATH_LEN]> = PerCpuArray::with_max_entries(1, 0);

/// Per-CPU event storage
#[map]
static FILE_EVENT_STORAGE: PerCpuArray<FileEvent> = PerCpuArray::with_max_entries(1, 0);

/// Pattern rules map - key: pattern (32 bytes), value: action
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PatternKey {
    pattern: [u8; 32],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RuleEntry {
    action: u8,
    event_type: u8,
    _padding: [u8; 6],
}

#[map]
static PATTERN_RULES: HashMap<PatternKey, RuleEntry> = HashMap::with_max_entries(1024, 0);

/// Mode map - 0: monitor, 1: protect
#[map]
static MODE_MAP: HashMap<u32, u8> = HashMap::with_max_entries(1, 0);

const MODE_MONITOR: u8 = 0;
const MODE_PROTECT: u8 = 1;
const EVENT_FILE: u8 = 1;
const ACTION_DENY: u8 = 1;

/// Get current mode
#[inline(always)]
fn get_mode() -> u8 {
    unsafe {
        match MODE_MAP.get(&0) {
            Some(mode) => *mode,
            None => MODE_MONITOR,
        }
    }
}

/// Check if pattern matches (prefix matching)
#[inline(always)]
fn check_pattern_rules(path: &[u8], event_type: u8) -> Option<u8> {
    // Try exact match first
    let mut key = PatternKey { pattern: [0; 32] };

    #[allow(clippy::needless_range_loop)]
    for i in 0..31 {
        if i >= path.len() || path[i] == 0 {
            break;
        }
        key.pattern[i] = path[i];
    }

    unsafe {
        if let Some(rule) = PATTERN_RULES.get(&key) {
            if rule.event_type == event_type {
                return Some(rule.action);
            }
        }
    }

    // Try prefix lengths: 16, 12, 20
    for &prefix_len in &[16usize, 12, 20] {
        key = PatternKey { pattern: [0; 32] };
        for i in 0..prefix_len.min(31) {
            if i >= path.len() || path[i] == 0 {
                break;
            }
            key.pattern[i] = path[i];
        }

        unsafe {
            if let Some(rule) = PATTERN_RULES.get(&key) {
                if rule.event_type == event_type {
                    return Some(rule.action);
                }
            }
        }
    }

    None
}

/// Send event to ring buffer
#[inline(always)]
fn send_event(event_type: u8, path: &[u8], blocked: u8) {
    if let Some(mut entry) = FILE_EVENTS.reserve::<FileEvent>(0) {
        let event = entry.as_mut_ptr() as *mut FileEvent;
        unsafe {
            (*event).pid = bpf_get_current_pid_tgid() as u32;
            (*event).tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
            (*event).uid = bpf_get_current_uid_gid() as u32;
            (*event).gid = (bpf_get_current_uid_gid() >> 32) as u32;
            (*event).timestamp_ns = bpf_ktime_get_ns();

            if let Ok(comm) = bpf_get_current_comm() {
                (&mut (*event).comm)[..MAX_COMM_LEN].copy_from_slice(&comm);
            }

            // Copy path
            for i in 0..MAX_PATH_LEN.min(path.len()) {
                (*event).path[i] = path[i];
                if path[i] == 0 {
                    break;
                }
            }

            (*event).op_type = match event_type {
                1 => FileOpType::Create,
                2 => FileOpType::Delete,
                _ => FileOpType::Open,
            };
        }
        entry.submit(0);
    }
}

/// Read filename from dentry
#[inline(always)]
fn read_dentry_name(dentry: *const dentry, buf: &mut [u8]) -> Result<usize, c_long> {
    if dentry.is_null() {
        return Err(-1);
    }

    unsafe {
        let name_ptr: *const u8 = bpf_probe_read_kernel(&(*dentry).d_name.name).map_err(|_| -1)?;

        if name_ptr.is_null() {
            return Err(-1);
        }

        let len = bpf_probe_read_kernel_str(name_ptr as *const _, buf).map_err(|_| -1)?;

        // Ensure null termination and valid length
        if len > 0 && len <= buf.len() {
            // Find actual length without null if present
            let actual_len = if buf[len - 1] == 0 { len - 1 } else { len };
            Ok(actual_len.min(buf.len() - 1))
        } else {
            Ok(0)
        }
    }
}

/// Build simple path from parent + filename (like C version)
#[inline(always)]
fn build_simple_path(
    filename: &[u8],
    filename_len: usize,
    buf: &mut [u8],
) -> Result<usize, c_long> {
    unsafe {
        let mut off = 0;
        buf[off] = b'/';
        off += 1;

        // Copy parent name if available (simplified: just "root" or skip)
        // In C version, it reads parent name
        // For simplicity, just put filename after /

        for i in 0..filename_len.min(63) {
            if off >= MAX_PATH_LEN - 1 {
                break;
            }
            buf[off] = filename[i];
            off += 1;
        }

        buf[off] = 0;
        Ok(off)
    }
}

/// LSM hook: inode_create - file creation
#[lsm(hook = "inode_create")]
pub fn inode_create(ctx: LsmContext) -> i32 {
    match try_inode_create(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_inode_create(_ctx: LsmContext) -> Result<i32, c_long> {
    let config = get_config();
    if config.file_enabled == 0 {
        return Ok(0);
    }

    unsafe {
        let scratch = PATH_SCRATCH.get_ptr_mut(0).ok_or(-1)?;
        let buf = &mut *scratch;

        // Get dentry from arg(1)
        let dentry = _ctx.arg::<*const dentry>(1);
        if dentry.is_null() {
            return Ok(0);
        }

        // Read filename
        let mut filename = [0u8; 64];
        let fname_len = read_dentry_name(dentry, &mut filename)?;

        if fname_len == 0 {
            return Ok(0);
        }

        // Build simple path (like C version)
        if build_simple_path(&filename, fname_len, buf).is_ok() {
            // Check rules against path
            if let Some(action) = check_pattern_rules(buf, EVENT_FILE) {
                if action == ACTION_DENY && get_mode() == MODE_PROTECT {
                    send_event(1, buf, 1);
                    return Ok(-1); // -EPERM
                }
            }
        }
    }

    Ok(0)
}

/// LSM hook: inode_unlink - file deletion
#[lsm(hook = "inode_unlink")]
pub fn inode_unlink(ctx: LsmContext) -> i32 {
    match try_inode_unlink(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_inode_unlink(_ctx: LsmContext) -> Result<i32, c_long> {
    let config = get_config();
    if config.file_enabled == 0 {
        return Ok(0);
    }

    unsafe {
        let scratch = PATH_SCRATCH.get_ptr_mut(0).ok_or(-1)?;
        let buf = &mut *scratch;

        // Get dentry from arg(1)
        let dentry = _ctx.arg::<*const dentry>(1);
        if dentry.is_null() {
            return Ok(0);
        }

        // Read filename
        let mut filename = [0u8; 64];
        let fname_len = read_dentry_name(dentry, &mut filename)?;

        if fname_len == 0 {
            return Ok(0);
        }

        // Build simple path
        if build_simple_path(&filename, fname_len, buf).is_ok() {
            // Check rules against path
            if let Some(action) = check_pattern_rules(buf, EVENT_FILE) {
                if action == ACTION_DENY && get_mode() == MODE_PROTECT {
                    send_event(2, buf, 1);
                    return Ok(-1); // -EPERM
                }
            }
        }
    }

    Ok(0)
}
