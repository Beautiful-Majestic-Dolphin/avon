use crate::compile::CompileError;
use crate::entities::SnapshotData;

pub fn encode(data: &SnapshotData) -> Vec<u8> {
    serde_json::to_vec(data).unwrap_or_default()
}

pub fn decode(bytes: &[u8]) -> Result<SnapshotData, CompileError> {
    serde_json::from_slice(bytes).map_err(|e| CompileError::Cedar(e.to_string()))
}
