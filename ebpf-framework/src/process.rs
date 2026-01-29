use ebpf_common::ProcessRule;
use ebpf_probes::ProcessProbe;

use crate::FrameworkError;

/// User-space controller for process policies.
pub struct ProcessController {
    probe: ProcessProbe,
    rules: Vec<ProcessRule>,
}

impl ProcessController {
    pub fn new(bpf_obj_path: &str) -> Self {
        Self {
            probe: ProcessProbe::new(bpf_obj_path),
            rules: Vec::new(),
        }
    }

    pub fn add_rule(&mut self, rule: ProcessRule) {
        self.rules.push(rule);
    }

    pub fn apply(&self) -> Result<(), FrameworkError> {
        self.probe.attach(&self.rules)?;
        Ok(())
    }
}
