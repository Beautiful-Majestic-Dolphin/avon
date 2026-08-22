use std::time::Duration;

/// Spec §6.3 defaults. Tests turn these right down.
#[derive(Clone, Debug)]
pub struct TimerConfig {
    pub keepalive: Duration,
    pub rekey_after: Duration,
    pub rekey_after_packets: u64,
    pub epoch_overlap: Duration,
    pub idle_timeout: Duration,
}

impl Default for TimerConfig {
    fn default() -> Self {
        Self {
            keepalive: Duration::from_secs(25),
            rekey_after: Duration::from_secs(120),
            rekey_after_packets: 1 << 32,
            epoch_overlap: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(180),
        }
    }
}
