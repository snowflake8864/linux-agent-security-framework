use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProbeError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Load error: {0}")]
    Load(String),
}

impl From<aya::maps::MapError> for ProbeError {
    fn from(err: aya::maps::MapError) -> Self {
        ProbeError::Load(format!("Map error: {}", err))
    }
}
