use thiserror::Error;

use ebpf_probes::ProbeError;

#[derive(Debug, Error)]
pub enum FrameworkError {
    #[error("probe error: {0}")]
    Probe(#[from] ProbeError),
}
