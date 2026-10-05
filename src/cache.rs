//! A single value that expires after a time-to-live. Memory only.

use std::time::{Duration, Instant};

pub struct TtlCell<T> {
    ttl: Duration,
    value: Option<(Instant, T)>,
}

impl<T> TtlCell<T> {
    pub fn new(ttl: Duration) -> Self {
        Self { ttl, value: None }
    }

    /// The value, unless it is missing, expired, or caching is disabled (`ttl == 0`).
    pub fn fresh(&self) -> Option<&T> {
        match &self.value {
            Some((stored, value)) if !self.ttl.is_zero() && stored.elapsed() < self.ttl => {
                Some(value)
            }
            _ => None,
        }
    }

    /// The stored value regardless of its age; used right after `set`.
    pub fn current(&self) -> Option<&T> {
        self.value.as_ref().map(|(_, value)| value)
    }

    pub fn set(&mut self, value: T) {
        self.value = Some((Instant::now(), value));
    }

    pub fn invalidate(&mut self) {
        self.value = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_is_fresh_until_it_expires() {
        let mut cell = TtlCell::new(Duration::from_millis(40));
        assert!(cell.fresh().is_none());
        cell.set(7);
        assert_eq!(cell.fresh(), Some(&7));
        std::thread::sleep(Duration::from_millis(60));
        assert!(cell.fresh().is_none());
        assert_eq!(cell.current(), Some(&7));
    }

    #[test]
    fn zero_ttl_disables_caching() {
        let mut cell = TtlCell::new(Duration::ZERO);
        cell.set(1);
        assert!(cell.fresh().is_none());
        assert_eq!(cell.current(), Some(&1));
    }

    #[test]
    fn invalidate_drops_the_value() {
        let mut cell = TtlCell::new(Duration::from_secs(60));
        cell.set(1);
        cell.invalidate();
        assert!(cell.fresh().is_none());
        assert!(cell.current().is_none());
    }
}
