//! Rate limiting for the AVON UDP Gateway.
//!
//! Provides per-IP rate limiting to prevent DoS attacks.

use dashmap::DashMap;
use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter as GovRateLimiter,
};
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::interval;
use tracing::{debug, info};

use crate::config::RateLimitConfig;

/// State for a single IP's rate limiter.
struct RateLimiterState {
    limiter: GovRateLimiter<NotKeyed, InMemoryState, DefaultClock>,
    last_seen: Instant,
}

/// Per-IP rate limiter for the gateway.
pub struct RateLimiter {
    limiters: DashMap<IpAddr, RateLimiterState>,
    config: RateLimitConfig,
}

impl RateLimiter {
    /// Creates a new rate limiter with the given configuration.
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            limiters: DashMap::new(),
            config,
        }
    }

    /// Checks if a request from the given IP is allowed.
    ///
    /// Returns `true` if the request is allowed, `false` if rate limited.
    pub fn check(&self, ip: IpAddr) -> bool {
        let now = Instant::now();

        // Get or create rate limiter for this IP
        let mut entry = self.limiters.entry(ip).or_insert_with(|| {
            let quota = Quota::per_second(
                NonZeroU32::new(self.config.requests_per_second).unwrap_or(NonZeroU32::MIN),
            )
            .allow_burst(NonZeroU32::new(self.config.burst_size).unwrap_or(NonZeroU32::MIN));
            RateLimiterState {
                limiter: GovRateLimiter::direct(quota),
                last_seen: now,
            }
        });

        // Update last seen time
        entry.last_seen = now;

        // Check if request is allowed
        entry.limiter.check().is_ok()
    }

    /// Periodically cleans up expired rate limiters.
    ///
    /// This should be spawned as a background task.
    pub async fn cleanup_expired(self: Arc<Self>) {
        let cleanup_duration = Duration::from_secs(self.config.cleanup_interval_secs);
        let mut ticker = interval(cleanup_duration);

        loop {
            ticker.tick().await;

            let now = Instant::now();
            let expiry_threshold = cleanup_duration * 2; // Keep for 2x cleanup interval

            let before_count = self.limiters.len();
            self.limiters
                .retain(|_, state| now.duration_since(state.last_seen) < expiry_threshold);
            let after_count = self.limiters.len();

            if before_count != after_count {
                info!(
                    removed = before_count - after_count,
                    remaining = after_count,
                    "Cleaned up expired rate limiters"
                );
            } else {
                debug!(count = after_count, "Rate limiter cleanup complete");
            }
        }
    }

    /// Returns the number of tracked IPs.
    pub fn tracked_ips(&self) -> usize {
        self.limiters.len()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn test_rate_limiter_allows_initial_requests() {
        let config = RateLimitConfig {
            requests_per_second: 10,
            burst_size: 20,
            cleanup_interval_secs: 60,
        };
        let limiter = RateLimiter::new(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // First requests should be allowed (within burst)
        for _ in 0..20 {
            assert!(limiter.check(ip));
        }
    }

    #[test]
    fn test_rate_limiter_blocks_after_burst() {
        let config = RateLimitConfig {
            requests_per_second: 1,
            burst_size: 2,
            cleanup_interval_secs: 60,
        };
        let limiter = RateLimiter::new(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Use up burst
        assert!(limiter.check(ip));
        assert!(limiter.check(ip));

        // Should be rate limited now
        assert!(!limiter.check(ip));
    }

    #[test]
    fn test_rate_limiter_different_ips() {
        let config = RateLimitConfig {
            requests_per_second: 1,
            burst_size: 1,
            cleanup_interval_secs: 60,
        };
        let limiter = RateLimiter::new(config);
        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();

        // Each IP gets its own limit
        assert!(limiter.check(ip1));
        assert!(limiter.check(ip2));

        // Both should be limited now
        assert!(!limiter.check(ip1));
        assert!(!limiter.check(ip2));
    }

    #[test]
    fn test_tracked_ips() {
        let config = RateLimitConfig::default();
        let limiter = RateLimiter::new(config);

        assert_eq!(limiter.tracked_ips(), 0);

        limiter.check("192.168.1.1".parse().unwrap());
        assert_eq!(limiter.tracked_ips(), 1);

        limiter.check("192.168.1.2".parse().unwrap());
        assert_eq!(limiter.tracked_ips(), 2);

        // Same IP doesn't increase count
        limiter.check("192.168.1.1".parse().unwrap());
        assert_eq!(limiter.tracked_ips(), 2);
    }
}
