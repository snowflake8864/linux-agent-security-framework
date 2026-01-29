pub mod error;
pub mod file;
pub mod process;
pub mod network;

pub use error::FrameworkError;
pub use file::FileController;
pub use process::ProcessController;
pub use network::NetworkController;

/// Top-level security framework facade that groups file, process and
/// network controllers. Controllers are internally decoupled and can be
/// used independently if desired.
pub struct SecurityFramework {
    pub file: FileController,
    pub process: ProcessController,
    pub network: NetworkController,
}

impl SecurityFramework {
    pub fn new(bpf_obj_path: &str) -> Self {
        Self {
            file: FileController::new(bpf_obj_path),
            process: ProcessController::new(bpf_obj_path),
            network: NetworkController::new(bpf_obj_path),
        }
    }
}
