use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttestationState {
    None,
    Unverified,
    Verified,
    Failed,
}

pub struct QuotePolicy {
    pub required_pcrs: Vec<u32>,
    pub max_age: Duration,
    pub allow_unknown_ak: bool,
}

impl Default for QuotePolicy {
    fn default() -> Self {
        Self {
            required_pcrs: vec![0, 7],
            max_age: Duration::from_secs(300),
            allow_unknown_ak: true,
        }
    }
}
