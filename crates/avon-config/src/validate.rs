use std::path::{Path, PathBuf};

use thiserror::Error;

/// Configuration validation errors. The `field` is the CLI flag name
/// (without dashes prefix), e.g. `database-url`, so operators can map it
/// to the flag or the corresponding `AVON_*` environment variable.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid value for --{field}: {reason}")]
    Invalid { field: &'static str, reason: String },
    #[error("file for --{field} does not exist: {path}")]
    MissingFile { field: &'static str, path: PathBuf },
}

/// Implemented by every argument group.
pub trait Validate {
    fn validate(&self) -> Result<(), ConfigError>;
}

pub(crate) fn require_file(field: &'static str, path: &Path) -> Result<(), ConfigError> {
    if path.is_file() {
        Ok(())
    } else {
        Err(ConfigError::MissingFile {
            field,
            path: path.to_path_buf(),
        })
    }
}

pub(crate) fn parse_url(field: &'static str, value: &str) -> Result<url::Url, ConfigError> {
    url::Url::parse(value).map_err(|e| ConfigError::Invalid {
        field,
        reason: e.to_string(),
    })
}
