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

    /// Mutable access to the value while it is still fresh.
    pub fn fresh_mut(&mut self) -> Option<&mut T> {
        match &mut self.value {
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
    fn a_fresh_value_can_be_updated_in_place() {
        let mut cell = TtlCell::new(Duration::from_secs(60));
        assert!(cell.fresh_mut().is_none());
        cell.set(vec![1]);
        cell.fresh_mut().unwrap().push(2);
        assert_eq!(cell.fresh(), Some(&vec![1, 2]));
        let mut disabled = TtlCell::new(Duration::ZERO);
        disabled.set(vec![1]);
        assert!(disabled.fresh_mut().is_none());
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
