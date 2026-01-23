//! OCSP Responder for the AVON Certificate Authority.
//!
//! This module provides OCSP response caching and management.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use tracing::{debug, info, warn};

use crate::ca::{CertificateAuthority, CertificateStatus, OcspStaple, Result};

pub struct CachedOcspResponse {
    pub response: Vec<u8>,
    pub this_update: DateTime<Utc>,
    pub next_update: DateTime<Utc>,
    pub status: CertificateStatus,
}

pub struct OcspResponder {
    ca: Arc<CertificateAuthority>,
    cache: DashMap<u64, CachedOcspResponse>,
    revoked: DashMap<u64, RevocationInfo>,
}

pub struct RevocationInfo {
    pub revoked_at: DateTime<Utc>,
    pub reason: String,
}

impl OcspResponder {
    pub fn new(ca: Arc<CertificateAuthority>) -> Self {
        Self {
            ca,
            cache: DashMap::new(),
            revoked: DashMap::new(),
        }
    }

    pub async fn get_response(&self, serial: u64) -> Result<OcspStaple> {
        if let Some(cached) = self.cache.get(&serial) {
            let now = Utc::now();
            if cached.next_update > now {
                debug!(serial, "Returning cached OCSP response");
                return Ok(OcspStaple {
                    response: cached.response.clone(),
                    this_update: cached.this_update,
                    next_update: cached.next_update,
                    status: cached.status,
                });
            }
        }

        let status = if self.revoked.contains_key(&serial) {
            CertificateStatus::Revoked
        } else {
            CertificateStatus::Good
        };

        let staple = self.ca.generate_ocsp_staple(serial, status)?;

        self.cache.insert(
            serial,
            CachedOcspResponse {
                response: staple.response.clone(),
                this_update: staple.this_update,
                next_update: staple.next_update,
                status: staple.status,
            },
        );

        debug!(serial, ?status, "Generated new OCSP response");
        Ok(staple)
    }

    pub fn revoke(&self, serial: u64, reason: String) {
        let now = Utc::now();
        self.revoked.insert(
            serial,
            RevocationInfo {
                revoked_at: now,
                reason,
            },
        );

        self.cache.remove(&serial);

        info!(serial, "Certificate revoked");
    }

    pub fn is_revoked(&self, serial: u64) -> bool {
        self.revoked.contains_key(&serial)
    }

    pub fn get_revocation_info(&self, serial: u64) -> Option<(DateTime<Utc>, String)> {
        self.revoked
            .get(&serial)
            .map(|info| (info.revoked_at, info.reason.clone()))
    }

    pub async fn refresh_all(&self) {
        let now = Utc::now();
        let mut expired_serials = Vec::new();

        for entry in self.cache.iter() {
            if entry.next_update <= now {
                expired_serials.push(*entry.key());
            }
        }

        for serial in expired_serials {
            self.cache.remove(&serial);
            if let Err(e) = self.get_response(serial).await {
                warn!(serial, error = %e, "Failed to refresh OCSP response");
            }
        }

        info!("OCSP cache refresh completed");
    }

    pub fn cleanup_expired(&self) {
        let now = Utc::now();
        let mut to_remove = Vec::new();

        for entry in self.cache.iter() {
            if entry.next_update <= now {
                to_remove.push(*entry.key());
            }
        }

        for serial in to_remove {
            self.cache.remove(&serial);
        }
    }

    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }

    pub fn revoked_count(&self) -> usize {
        self.revoked.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CaConfig;

    async fn create_test_responder() -> OcspResponder {
        let config = CaConfig::default();
        let ca = Arc::new(CertificateAuthority::new(&config).await.unwrap());
        OcspResponder::new(ca)
    }

    #[tokio::test]
    async fn test_get_response() {
        let responder = create_test_responder().await;

        let response = responder.get_response(1).await.unwrap();
        assert!(!response.response.is_empty());
        assert_eq!(response.status, CertificateStatus::Good);
    }

    #[tokio::test]
    async fn test_cache_hit() {
        let responder = create_test_responder().await;

        let response1 = responder.get_response(1).await.unwrap();
        let response2 = responder.get_response(1).await.unwrap();

        assert_eq!(response1.response, response2.response);
        assert_eq!(responder.cache_size(), 1);
    }

    #[tokio::test]
    async fn test_revocation() {
        let responder = create_test_responder().await;

        responder.revoke(1, "Test revocation".to_string());

        assert!(responder.is_revoked(1));

        let response = responder.get_response(1).await.unwrap();
        assert_eq!(response.status, CertificateStatus::Revoked);
    }

    #[tokio::test]
    async fn test_revocation_info() {
        let responder = create_test_responder().await;

        responder.revoke(1, "Security incident".to_string());

        let info = responder.get_revocation_info(1);
        assert!(info.is_some());
        let (_, reason) = info.unwrap();
        assert_eq!(reason, "Security incident");
    }
}
