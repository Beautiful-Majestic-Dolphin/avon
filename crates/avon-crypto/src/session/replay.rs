use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};

/// Sliding-window anti-replay check over 2048 counters.
pub struct ReplayWindow {
    seen: HashSet<u64>,
    highest: Option<u64>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReplayError {
    Replayed,
    TooOld,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    pub const SIZE: u64 = 2048;

    pub fn new() -> Self {
        Self {
            seen: HashSet::new(),
            highest: None,
        }
    }

    pub fn highest(&self) -> Option<u64> {
        self.highest
    }

    pub fn check_and_update(&mut self, counter: u64) -> Result<(), ReplayError> {
        match self.highest {
            None => {
                self.seen.insert(counter);
                self.highest = Some(counter);
                Ok(())
            }
            Some(highest) if counter > highest => {
                // Advance: prune entries that are now too old
                let diff = counter - highest;
                if diff >= Self::SIZE {
                    self.seen.clear();
                } else {
                    // Window is (counter - SIZE +1 ..= counter), keep only those
                    self.seen.retain(|&c| counter - c < Self::SIZE);
                }
                self.seen.insert(counter);
                self.highest = Some(counter);
                Ok(())
            }
            Some(highest) => {
                if highest - counter >= Self::SIZE {
                    return Err(ReplayError::TooOld);
                }
                if !self.seen.insert(counter) {
                    return Err(ReplayError::Replayed);
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug)]
pub struct CounterExhausted;

impl std::fmt::Display for CounterExhausted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("send counter exhausted")
    }
}
impl std::error::Error for CounterExhausted {}

/// Monotonic send counter. The last value (`u64::MAX - 1` and above) is
/// never handed out; once reached the counter stays poisoned so a nonce can
/// never repeat even if callers keep calling `next()`.
pub struct SendCounter(AtomicU64);

impl Default for SendCounter {
    fn default() -> Self {
        Self::new()
    }
}

impl SendCounter {
    const LIMIT: u64 = u64::MAX - 1;

    pub fn new() -> Self {
        Self(AtomicU64::new(0))
    }
    pub fn starting_at(value: u64) -> Self {
        Self(AtomicU64::new(value))
    }

    pub fn next(&self) -> Result<u64, CounterExhausted> {
        let mut current = self.0.load(Ordering::SeqCst);
        loop {
            if current >= Self::LIMIT {
                return Err(CounterExhausted);
            }
            match self
                .0
                .compare_exchange(current, current + 1, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => return Ok(current),
                Err(actual) => current = actual,
            }
        }
    }

    pub fn remaining(&self) -> u64 {
        Self::LIMIT.saturating_sub(self.0.load(Ordering::SeqCst))
    }
}
