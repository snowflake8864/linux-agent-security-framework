use aya::Bpf;
use ebpf_common::ProcessRule;

use crate::ProbeError;

/// Abstraction over process-related eBPF programs (e.g., sched_process_exec).
pub struct ProcessProbe {
    bpf_obj_path: String,
}

impl ProcessProbe {
    pub fn new<P: Into<String>>(bpf_obj_path: P) -> Self {
        Self {
            bpf_obj_path: bpf_obj_path.into(),
        }
    }

    pub fn attach(&self, _rules: &[ProcessRule]) -> Result<(), ProbeError> {
        let _bpf = Bpf::load_file(&self.bpf_obj_path)
            .map_err(|e| ProbeError::Load(format!("Failed to load BPF object: {}", e)))?;

        // Attach sched_process_exec / LSM hooks here.
        Ok(())
    }
}
