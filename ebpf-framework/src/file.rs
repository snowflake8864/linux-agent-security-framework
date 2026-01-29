use ebpf_common::FileRule;
use ebpf_probes::FileProbe;

use crate::FrameworkError;

/// User-space controller for file policies.
///
/// This is a pure control-plane abstraction and does not depend on other
/// controllers.
pub struct FileController {
    probe: FileProbe,
    rules: Vec<FileRule>,
}

impl FileController {
    pub fn new(bpf_obj_path: &str) -> Self {
        Self {
            probe: FileProbe::new(bpf_obj_path),
            rules: Vec::new(),
        }
    }

    pub fn add_rule(&mut self, rule: FileRule) {
        self.rules.push(rule);
    }

    pub fn apply(&self) -> Result<(), FrameworkError> {
        self.probe.attach(&self.rules)?;
        Ok(())
    }
}
