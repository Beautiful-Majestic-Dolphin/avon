use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    #[error("invalid uuid bytes (len {0})")]
    InvalidUuid(usize),
}

pub fn uuid_to_bytes(id: Uuid) -> Vec<u8> {
    id.as_bytes().to_vec()
}

pub fn bytes_to_uuid(b: &[u8]) -> Result<Uuid, ProtoError> {
    let arr: [u8; 16] = b.try_into().map_err(|_| ProtoError::InvalidUuid(b.len()))?;
    Ok(Uuid::from_bytes(arr))
}

pub fn now_ts() -> prost_types::Timestamp {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    prost_types::Timestamp {
        seconds: now.as_secs() as i64,
        nanos: now.subsec_nanos() as i32,
    }
}
