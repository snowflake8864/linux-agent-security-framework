use aya::Btf;
use aya::{programs::Lsm, Bpf};
use ebpf_common::FileRule;

use crate::ProbeError;

/// Abstraction over file-related eBPF programs (LSM / kprobe / tracepoint).
///
/// This crate focuses on the Rust-side control plane. The actual eBPF
/// bytecode (C/Rust BPF) should be compiled separately into an object file
/// and loaded by aya.
pub struct FileProbe {
    /// Path to the compiled BPF object that implements file policies.
    bpf_obj_path: String,
}

impl FileProbe {
    pub fn new<P: Into<String>>(bpf_obj_path: P) -> Self {
        Self {
            bpf_obj_path: bpf_obj_path.into(),
        }
    }

    /// Load the BPF object and attach file-related hooks.
    pub fn attach(&self, _rules: &[FileRule]) -> Result<(), ProbeError> {
        // NOTE: Real implementation should:
        // 1. Load BPF object via aya.
        // 2. Populate BPF maps with rules (converted to fixed-size keys).
        // 3. Attach LSM hooks / kprobes.
        let mut bpf = Bpf::load_file(&self.bpf_obj_path)
            .map_err(|e| ProbeError::Load(format!("Failed to load BPF object: {}", e)))?;

        // Load BTF for LSM programs
        let btf = Btf::from_sys_fs()
            .map_err(|e| ProbeError::Load(format!("Failed to load BTF: {}", e)))?;

        // Attach LSM hooks here if needed
        // Example: attach inode_create LSM hook
        if let Some(prog) = bpf.program_mut("enforce_inode_create") {
            let lsm_prog: &mut Lsm = prog
                .try_into()
                .map_err(|e| ProbeError::Load(format!("Failed to convert to LSM: {}", e)))?;
            lsm_prog
                .load("inode_create", &btf)
                .map_err(|e| ProbeError::Load(format!("Failed to load LSM inode_create: {}", e)))?;
            lsm_prog.attach().map_err(|e| {
                ProbeError::Load(format!("Failed to attach LSM inode_create: {}", e))
            })?;
        }

        // Placeholder: you would look up a program by name and attach it.
        // Keep stack usage minimal in BPF side; use maps for larger state.
        Ok(())
    }
}
