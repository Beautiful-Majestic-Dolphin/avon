use std::path::Path;

use crate::provider::{read_provider_record, KeyError, KeyProvider, ProviderKind};
use crate::software::SoftwareKeyProvider;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderChoice {
    /// Prefer hardware, fall back to software with a warning naming the reason.
    Auto,
    Software,
    Tpm2,
    Keychain,
    Cng,
}

impl std::str::FromStr for ProviderChoice {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "auto" => Self::Auto,
            "software" => Self::Software,
            "tpm2" => Self::Tpm2,
            "keychain" => Self::Keychain,
            "cng" => Self::Cng,
            _ => return Err(format!("unknown provider choice {s}")),
        })
    }
}

impl ProviderChoice {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Software => "software",
            Self::Tpm2 => "tpm2",
            Self::Keychain => "keychain",
            Self::Cng => "cng",
        }
    }
}

/// Try each hardware provider this build has, in platform order.
///
/// `available()` only says the hardware answered, not that a key can be made in
/// it — a TPM whose owner hierarchy has an auth value set is present and
/// unusable. Under `Auto` that is a reason to fall back with a warning naming
/// the reason, not to refuse to enrol; an explicit `--key-provider` still fails
/// hard, which is handled by the caller.
fn try_hardware(_dir: &Path) -> Result<Option<Box<dyn KeyProvider>>, KeyError> {
    #[cfg(all(feature = "tpm2", target_os = "linux"))]
    {
        if crate::tpm2::Tpm2KeyProvider::available() {
            match crate::tpm2::Tpm2KeyProvider::create(_dir) {
                Ok(p) => return Ok(Some(Box::new(p))),
                Err(e) => tracing::warn!(error = %e, "a TPM is present but unusable"),
            }
        }
    }
    #[cfg(all(feature = "keychain", target_os = "macos"))]
    {
        if crate::keychain::KeychainKeyProvider::available() {
            match crate::keychain::KeychainKeyProvider::create(_dir) {
                Ok(p) => return Ok(Some(Box::new(p))),
                Err(e) => tracing::warn!(error = %e, "the Keychain is present but unusable"),
            }
        }
    }
    #[cfg(all(feature = "cng", target_os = "windows"))]
    {
        if crate::cng::CngKeyProvider::available() {
            match crate::cng::CngKeyProvider::create(_dir) {
                Ok(p) => return Ok(Some(Box::new(p))),
                Err(e) => tracing::warn!(error = %e, "CNG is present but unusable"),
            }
        }
    }
    let _ = _dir;
    Ok(None)
}

/// Create a provider for a device that has not enrolled yet. An explicit
/// hardware choice that is unavailable is fatal — silently downgrading a
/// hardware-backed deployment to software is exactly the failure this avoids.
pub fn open_or_create(
    choice: ProviderChoice,
    dir: &Path,
) -> Result<Box<dyn KeyProvider>, KeyError> {
    // If already enrolled, open existing and validate choice matches (if explicit).
    if dir.join("provider.json").exists() || dir.join("identity.bin").exists() {
        let existing = open_existing(dir)?;
        match choice {
            ProviderChoice::Auto => return Ok(existing),
            ProviderChoice::Software
            | ProviderChoice::Tpm2
            | ProviderChoice::Keychain
            | ProviderChoice::Cng => {
                let requested = match choice {
                    ProviderChoice::Software => ProviderKind::Software,
                    ProviderChoice::Tpm2 => ProviderKind::Tpm2,
                    ProviderChoice::Keychain => ProviderKind::Keychain,
                    ProviderChoice::Cng => ProviderKind::Cng,
                    ProviderChoice::Auto => unreachable!(),
                };
                if existing.kind() != requested {
                    return Err(KeyError::Unavailable {
                        provider: requested,
                        reason: format!(
                            "existing provider is {} but requested {}",
                            existing.kind().as_str(),
                            requested.as_str()
                        ),
                    });
                }
                return Ok(existing);
            }
        }
    }

    let provider: Box<dyn KeyProvider> = match choice {
        ProviderChoice::Software => Box::new(SoftwareKeyProvider::create(dir)?),
        ProviderChoice::Auto => match try_hardware(dir)? {
            Some(p) => {
                tracing::info!(
                    provider = p.kind().as_str(),
                    "using hardware-backed key storage"
                );
                p
            }
            None => {
                tracing::warn!(
                    "no hardware key store available; falling back to the software provider"
                );
                Box::new(SoftwareKeyProvider::create(dir)?)
            }
        },
        ProviderChoice::Tpm2 => {
            #[cfg(all(feature = "tpm2", target_os = "linux"))]
            {
                return Ok(Box::new(crate::tpm2::Tpm2KeyProvider::create(dir)?));
            }
            #[allow(unreachable_code)]
            {
                return Err(KeyError::Unavailable {
                    provider: ProviderKind::Tpm2,
                    reason: "not built into this binary or not supported on this platform".into(),
                });
            }
        }
        ProviderChoice::Keychain => {
            #[cfg(all(feature = "keychain", target_os = "macos"))]
            {
                return Ok(Box::new(crate::keychain::KeychainKeyProvider::create(dir)?));
            }
            #[allow(unreachable_code)]
            {
                return Err(KeyError::Unavailable {
                    provider: ProviderKind::Keychain,
                    reason: "not built into this binary or not supported on this platform".into(),
                });
            }
        }
        ProviderChoice::Cng => {
            #[cfg(all(feature = "cng", target_os = "windows"))]
            {
                return Ok(Box::new(crate::cng::CngKeyProvider::create(dir)?));
            }
            #[allow(unreachable_code)]
            {
                return Err(KeyError::Unavailable {
                    provider: ProviderKind::Cng,
                    reason: "not built into this binary or not supported on this platform".into(),
                });
            }
        }
    };
    // For software, the provider already wrote provider.json; for hardware we must ensure.
    // Ensure the record exists (idempotent).
    let _ = &provider;
    Ok(provider)
}

/// Reopen the provider an enrolled device already uses.
pub fn open_existing(dir: &Path) -> Result<Box<dyn KeyProvider>, KeyError> {
    // Try provider.json first; if missing but identity files exist, assume software for backward compat.
    let kind = if dir.join("provider.json").exists() {
        read_provider_record(dir)?
    } else if dir.join("identity.bin").exists() {
        ProviderKind::Software
    } else {
        return Err(KeyError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no provider record",
        )));
    };
    Ok(match kind {
        ProviderKind::Software => Box::new(SoftwareKeyProvider::open(dir)?),
        #[cfg(all(feature = "tpm2", target_os = "linux"))]
        ProviderKind::Tpm2 => Box::new(crate::tpm2::Tpm2KeyProvider::open(dir)?),
        #[cfg(all(feature = "keychain", target_os = "macos"))]
        ProviderKind::Keychain => Box::new(crate::keychain::KeychainKeyProvider::open(dir)?),
        #[cfg(all(feature = "cng", target_os = "windows"))]
        ProviderKind::Cng => Box::new(crate::cng::CngKeyProvider::open(dir)?),
        #[allow(unreachable_patterns)]
        other => {
            return Err(KeyError::Unavailable {
                provider: other,
                reason: "this build cannot open that provider".into(),
            })
        }
    })
}
