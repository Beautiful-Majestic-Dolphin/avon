//! Session tokens: random 32-byte bearer tokens kept in Redis, bound to the
//! device's tenant, id and TLS certificate hash.

use avon_common::ids::{DeviceId, TenantId};
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use tonic::Status;

#[derive(Clone)]
pub struct SessionStore {
    redis: ConnectionManager,
    ttl_secs: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SessionInfo {
    pub tenant: TenantId,
    pub device: DeviceId,
    #[serde(with = "hex_arr")]
    pub tls_cert_sha256: [u8; 32],
    pub issued_at: i64,
}

mod hex_arr {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(s).map_err(serde::de::Error::custom)?;
        v.try_into().map_err(|_| serde::de::Error::custom("len"))
    }
}

fn key(token: &[u8; 32]) -> String {
    format!("avon:session:{}", hex::encode(token))
}

fn revoked_key(device: DeviceId) -> String {
    format!("avon:device-revoked:{device}")
}

impl SessionStore {
    pub fn new(redis: ConnectionManager, ttl_secs: u64) -> Self {
        Self { redis, ttl_secs }
    }

    pub async fn issue(
        &self,
        tenant: TenantId,
        device: DeviceId,
        tls_cert_sha256: [u8; 32],
    ) -> Result<[u8; 32], Status> {
        let token =
            avon_crypto::random::random_bytes_fixed::<32>().map_err(|_| Status::internal("rng"))?;
        let info = SessionInfo {
            tenant,
            device,
            tls_cert_sha256,
            issued_at: chrono::Utc::now().timestamp(),
        };
        let mut r = self.redis.clone();
        let _: () = r
            .set_ex(
                key(&token),
                serde_json::to_string(&info).map_err(|_| Status::internal("encode"))?,
                self.ttl_secs,
            )
            .await
            .map_err(|_| Status::unavailable("session store"))?;
        Ok(token)
    }

    pub async fn lookup(&self, token: &[u8; 32]) -> Result<Option<SessionInfo>, Status> {
        let mut r = self.redis.clone();
        let raw: Option<String> = r
            .get(key(token))
            .await
            .map_err(|_| Status::unavailable("session store"))?;
        let Some(raw) = raw else { return Ok(None) };
        let info: SessionInfo =
            serde_json::from_str(&raw).map_err(|_| Status::internal("decode"))?;
        let revoked: bool = r
            .exists(revoked_key(info.device))
            .await
            .map_err(|_| Status::unavailable("session store"))?;
        if revoked {
            return Ok(None);
        }
        Ok(Some(info))
    }

    pub async fn revoke_device(&self, device: DeviceId) -> Result<(), Status> {
        let mut r = self.redis.clone();
        let _: () = r
            .set_ex(revoked_key(device), 1, self.ttl_secs)
            .await
            .map_err(|_| Status::unavailable("session store"))?;
        Ok(())
    }
}
