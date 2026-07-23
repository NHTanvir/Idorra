//! The mandatory pacing primitives: a requests-per-second token bucket
//! (`governor`) plus a hard in-flight concurrency cap (`tokio` semaphore).
//!
//! Order of use at the gate is **token then permit**: the limiter paces how fast
//! requests *start*; the permit then bounds how many are *in flight* and is held
//! only for the actual request duration.

use crate::error::{Error, Result};
use governor::{Quota, RateLimiter};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

type DirectRateLimiter = governor::DefaultDirectRateLimiter;

/// A held concurrency permit; the in-flight slot is released on drop.
pub struct InFlightPermit {
    _permit: OwnedSemaphorePermit,
}

/// Combined rate limiter + concurrency cap, shared across all worker tasks.
#[derive(Clone)]
pub struct Limiter {
    semaphore: Arc<Semaphore>,
    rate: Arc<DirectRateLimiter>,
}

impl Limiter {
    /// Build a limiter. `requests_per_second` may be fractional (e.g. `0.5`);
    /// `burst` is the token-bucket allowance (min 1); `max_concurrency` is the
    /// hard in-flight ceiling (min 1).
    pub fn new(requests_per_second: f64, burst: u32, max_concurrency: usize) -> Result<Self> {
        if !(requests_per_second > 0.0) || !requests_per_second.is_finite() {
            return Err(Error::Config(format!(
                "requests_per_second must be a positive, finite number (got {requests_per_second})"
            )));
        }
        // Build the quota from a period so fractional rates work uniformly.
        let period = Duration::from_secs_f64(1.0 / requests_per_second);
        let quota = Quota::with_period(period)
            .ok_or_else(|| Error::Config("computed rate-limit period was zero".into()))?
            .allow_burst(NonZeroU32::new(burst.max(1)).expect("burst.max(1) >= 1"));

        let concurrency = max_concurrency.max(1);
        Ok(Self {
            semaphore: Arc::new(Semaphore::new(concurrency)),
            rate: Arc::new(RateLimiter::direct(quota)),
        })
    }

    /// Wait for a rate-limit token, then acquire an in-flight permit. Hold the
    /// returned permit until the request completes.
    pub async fn acquire(&self) -> InFlightPermit {
        self.rate.until_ready().await;
        let permit = self
            .semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore is never closed for the lifetime of a run");
        InFlightPermit { _permit: permit }
    }

    /// Current number of free in-flight permits (for tests/telemetry).
    pub fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_nonpositive_rate() {
        assert!(Limiter::new(0.0, 1, 1).is_err());
        assert!(Limiter::new(-1.0, 1, 1).is_err());
        assert!(Limiter::new(f64::NAN, 1, 1).is_err());
    }

    #[tokio::test]
    async fn concurrency_cap_is_enforced() {
        let limiter = Limiter::new(1000.0, 1000, 2).unwrap();
        let _p1 = limiter.acquire().await;
        let _p2 = limiter.acquire().await;
        assert_eq!(limiter.available_permits(), 0);
        // A third acquire must not resolve while both permits are held.
        let pending =
            tokio::time::timeout(Duration::from_millis(50), limiter.acquire()).await;
        assert!(pending.is_err(), "third acquire should block at the cap");
    }

    #[tokio::test]
    async fn fractional_rate_is_accepted() {
        // 0.5 rps => one request per 2s; construction must succeed.
        assert!(Limiter::new(0.5, 1, 1).is_ok());
    }
}
