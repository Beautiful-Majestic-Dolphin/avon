#![allow(clippy::unwrap_used, clippy::expect_used)]

use avon_crypto::session::{ReplayError, ReplayWindow, SendCounter};
use proptest::prelude::*;

#[test]
fn accepts_in_order_and_rejects_replay() {
    let mut w = ReplayWindow::new();
    w.check_and_update(0).unwrap();
    w.check_and_update(1).unwrap();
    assert_eq!(w.check_and_update(1), Err(ReplayError::Replayed));
    assert_eq!(w.check_and_update(0), Err(ReplayError::Replayed));
    w.check_and_update(5).unwrap();
    w.check_and_update(3).unwrap(); // out of order inside window is fine
    assert_eq!(w.check_and_update(3), Err(ReplayError::Replayed));
    assert_eq!(w.highest(), Some(5));
}

#[test]
fn rejects_counters_older_than_the_window() {
    let mut w = ReplayWindow::new();
    w.check_and_update(10_000).unwrap();
    assert_eq!(
        w.check_and_update(10_000 - ReplayWindow::SIZE),
        Err(ReplayError::TooOld)
    );
    w.check_and_update(10_000 - ReplayWindow::SIZE + 1).unwrap();
}

#[test]
fn large_jump_forward_clears_old_state() {
    let mut w = ReplayWindow::new();
    w.check_and_update(1).unwrap();
    w.check_and_update(1_000_000).unwrap();
    assert_eq!(w.check_and_update(1), Err(ReplayError::TooOld));
    w.check_and_update(999_999).unwrap();
    assert_eq!(w.check_and_update(999_999), Err(ReplayError::Replayed));
}

#[test]
fn counter_poisons_at_exhaustion() {
    let c = SendCounter::new();
    assert_eq!(c.next().unwrap(), 0);
    assert_eq!(c.next().unwrap(), 1);
    // Fast-forward by constructing near the end.
    let c = SendCounter::starting_at(u64::MAX - 2);
    assert_eq!(c.next().unwrap(), u64::MAX - 2);
    assert!(c.next().is_err());
    assert!(
        c.next().is_err(),
        "counter must stay poisoned, never wrap to 0"
    );
}

proptest! {
    #[test]
    fn never_accepts_a_counter_twice(counters in proptest::collection::vec(0u64..5000, 1..2000)) {
        let mut w = ReplayWindow::new();
        let mut accepted = std::collections::HashSet::new();
        for c in counters {
            if w.check_and_update(c).is_ok() {
                prop_assert!(accepted.insert(c), "counter {c} accepted twice");
            }
        }
    }

    #[test]
    fn strictly_increasing_sequences_are_all_accepted(start in 0u64..1_000_000, len in 1usize..3000) {
        let mut w = ReplayWindow::new();
        for c in start..start + len as u64 {
            prop_assert!(w.check_and_update(c).is_ok());
        }
    }
}
