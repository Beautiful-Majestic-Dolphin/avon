//! AVON wire contracts (protobuf package `avon.v2`) and small helpers.
pub mod v2 {
    tonic::include_proto!("avon.v2");
}

mod helpers;
pub use helpers::{bytes_to_uuid, now_ts, uuid_to_bytes, ProtoError};
