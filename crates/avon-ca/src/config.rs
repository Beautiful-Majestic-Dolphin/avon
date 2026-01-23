//! Configuration for the AVON Certificate Authority service.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CaConfig {
    pub listen_addr: String,

    #[serde(default)]
    pub root_key_path: Option<String>,

    #[serde(default)]
    pub intermediate_key_path: Option<String>,

    #[serde(default)]
    pub cert_lifetime_secs: Option<u64>,

    #[serde(default)]
    pub ocsp_lifetime_secs: Option<u64>,

    #[serde(default)]
    pub initial_serial: Option<u64>,

    #[serde(default)]
    pub database_url: Option<String>,
}

impl Default for CaConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:50052".to_string(),
            root_key_path: None,
            intermediate_key_path: None,
            cert_lifetime_secs: Some(3600),
            ocsp_lifetime_secs: Some(3600),
            initial_serial: Some(1),
            database_url: None,
        }
    }
}

impl CaConfig {
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(addr) = std::env::var("CA_LISTEN_ADDR") {
            config.listen_addr = addr;
        }

        if let Ok(path) = std::env::var("CA_ROOT_KEY_PATH") {
            config.root_key_path = Some(path);
        }

        if let Ok(path) = std::env::var("CA_INTERMEDIATE_KEY_PATH") {
            config.intermediate_key_path = Some(path);
        }

        if let Ok(lifetime) = std::env::var("CA_CERT_LIFETIME_SECS") {
            if let Ok(secs) = lifetime.parse() {
                config.cert_lifetime_secs = Some(secs);
            }
        }

        if let Ok(lifetime) = std::env::var("CA_OCSP_LIFETIME_SECS") {
            if let Ok(secs) = lifetime.parse() {
                config.ocsp_lifetime_secs = Some(secs);
            }
        }

        if let Ok(serial) = std::env::var("CA_INITIAL_SERIAL") {
            if let Ok(s) = serial.parse() {
                config.initial_serial = Some(s);
            }
        }

        if let Ok(url) = std::env::var("DATABASE_URL") {
            config.database_url = Some(url);
        }

        config
    }
}
