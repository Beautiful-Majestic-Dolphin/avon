#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttestationState {
    None,
    Unverified,
    Verified,
    Failed,
}

impl AttestationState {
    /// The spelling used by the `attestation_state` enum in the database and by
    /// the policy engine.
    pub fn as_str(&self) -> &'static str {
        match self {
            AttestationState::None => "none",
            AttestationState::Unverified => "unverified",
            AttestationState::Verified => "verified",
            AttestationState::Failed => "failed",
        }
    }
}

#[derive(Clone, Debug)]
pub struct QuotePolicy {
    /// PCRs that must appear in the quote's selection. 0 covers the firmware
    /// code, 7 the secure-boot state.
    pub required_pcrs: Vec<u32>,
    /// Accept a device whose attestation key we have not seen before, and
    /// remember it. Turning this off means every AK must be pre-registered.
    pub allow_unknown_ak: bool,
    /// Refuse a quote whose TPM says its clock may have moved backwards.
    pub require_safe_clock: bool,
}

impl Default for QuotePolicy {
    fn default() -> Self {
        Self {
            required_pcrs: vec![0, 7],
            allow_unknown_ak: true,
            require_safe_clock: true,
        }
    }
}
