use aya::{maps::HashMap, Bpf};
use ebpf_common::{Action, NetworkRule};

use crate::ProbeError;

pub struct NetworkProbe {
    bpf: Bpf,
}

impl NetworkProbe {
    pub fn new<P: Into<String>>(bpf_obj_path: P) -> Self {
        Self {
            bpf: Bpf::load_file(bpf_obj_path.into()).expect("Failed to load BPF object"),
        }
    }

    pub fn load_bpf(self) -> Result<Bpf, ProbeError> {
        Ok(self.bpf)
    }

    pub fn attach(&self, _rules: &[NetworkRule]) -> Result<(), ProbeError> {
        // Placeholder for network attachment
        Ok(())
    }

    pub fn configure_blocking_rules(bpf: &mut Bpf, rules: &[NetworkRule]) -> Result<(), ProbeError> {
        let mut block_map: HashMap<_, u16, u8> = HashMap::try_from(
            bpf.map_mut("block_rules")
                .ok_or_else(|| ProbeError::Load("block_rules map not found".to_string()))?,
        )
        .map_err(|e| ProbeError::Load(format!("Failed to access block_rules map: {}", e)))?;

        for rule in rules {
            if rule.action == Action::Deny {
                block_map.insert(rule.local_port, 1, 0)?;
            }
        }

        Ok(())
    }
}
