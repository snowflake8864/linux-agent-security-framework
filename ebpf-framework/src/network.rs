use ebpf_common::NetworkRule;
use ebpf_probes::NetworkProbe;

use crate::FrameworkError;

/// User-space controller for network policies, including redirect rules.
pub struct NetworkController {
    probe: NetworkProbe,
    rules: Vec<NetworkRule>,
}

impl NetworkController {
    pub fn new(bpf_obj_path: &str) -> Self {
        Self {
            probe: NetworkProbe::new(bpf_obj_path),
            rules: Vec::new(),
        }
    }

    pub fn add_rule(&mut self, rule: NetworkRule) {
        self.rules.push(rule);
    }

    /// Apply all configured rules.
    ///
    /// Implementation detail: redirect rules are translated into
    /// compact map entries in the kernel, which avoids large stack usage
    /// inside the BPF program.
    pub fn apply(&mut self) -> Result<(), FrameworkError> {
        self.probe.attach(&self.rules)?;
        Ok(())
    }
}
