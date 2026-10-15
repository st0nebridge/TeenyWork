//! @module expiring
//! @description A bounded in-memory table whose entries expire: the
//! Challenger's live challenges, work leases and access-token grants.
//!
//! @input Entries keyed by string, each with an expiry; the current time.
//! @output Lookups, removals, and inserts that are refused when the table is
//! full of live entries.
//! @dependencies `chrono`. Used by `main.rs` (`AppState`).
//!
//! Without a cap, anyone able to request challenges grows these tables for as
//! long as entries live (15 minutes for a challenge), until the process runs
//! out of memory. Expired entries are swept at most once a second, so an
//! insert costs O(1) amortized instead of a scan of the whole table. A lookup
//! may still return an entry that expired since the last sweep, so callers
//! check the expiry of what they read, as they always have.

use chrono::{DateTime, TimeDelta, Utc};
use std::collections::HashMap;

/// Something with an expiry time.
pub trait Expiring {
    fn expires_at(&self) -> DateTime<Utc>;
}

/// The insert was refused: every slot holds a live entry.
#[derive(Debug, PartialEq, Eq)]
pub struct TableFull;

/// Longest a table goes between sweeps of its expired entries.
fn sweep_interval() -> TimeDelta {
    TimeDelta::seconds(1)
}

pub struct ExpiringTable<V> {
    entries: HashMap<String, V>,
    capacity: usize,
    last_sweep: Option<DateTime<Utc>>,
}

impl<V: Expiring> ExpiringTable<V> {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            capacity,
            last_sweep: None,
        }
    }

    pub fn get(&self, key: &str) -> Option<&V> {
        self.entries.get(key)
    }

    pub fn remove(&mut self, key: &str) -> Option<V> {
        self.entries.remove(key)
    }

    #[cfg(test)]
    pub fn contains_key(&self, key: &str) -> bool {
        self.entries.contains_key(key)
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Drops entries expired at `now`, unless a sweep ran less than the sweep
    /// interval ago. A clock that has gone backwards sweeps again.
    fn sweep(&mut self, now: DateTime<Utc>) {
        if let Some(last) = self.last_sweep {
            if now >= last && now - last < sweep_interval() {
                return;
            }
        }
        self.entries.retain(|_, entry| entry.expires_at() > now);
        self.last_sweep = Some(now);
    }

    /// Whether an insert of a new key would be accepted now.
    pub fn has_room(&mut self, now: DateTime<Utc>) -> bool {
        self.sweep(now);
        self.entries.len() < self.capacity
    }

    /// Inserts `value`, replacing any entry under `key`. A new key is refused
    /// when the table holds `capacity` entries after sweeping.
    pub fn insert(&mut self, key: String, value: V, now: DateTime<Utc>) -> Result<(), TableFull> {
        self.sweep(now);
        if self.entries.len() >= self.capacity && !self.entries.contains_key(&key) {
            return Err(TableFull);
        }
        self.entries.insert(key, value);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Entry(DateTime<Utc>);

    impl Expiring for Entry {
        fn expires_at(&self) -> DateTime<Utc> {
            self.0
        }
    }

    fn at(seconds: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000 + seconds, 0).unwrap()
    }

    #[test]
    fn a_full_table_refuses_new_keys_but_replaces_existing_ones() {
        let mut table = ExpiringTable::new(2);
        assert_eq!(table.insert("a".into(), Entry(at(100)), at(0)), Ok(()));
        assert_eq!(table.insert("b".into(), Entry(at(100)), at(0)), Ok(()));
        assert_eq!(
            table.insert("c".into(), Entry(at(100)), at(0)),
            Err(TableFull)
        );
        assert!(!table.has_room(at(0)));
        assert_eq!(table.insert("a".into(), Entry(at(200)), at(0)), Ok(()));
        assert_eq!(table.get("a").map(|entry| entry.0), Some(at(200)));
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn expired_entries_free_their_slots_at_the_next_sweep() {
        let mut table = ExpiringTable::new(2);
        table.insert("a".into(), Entry(at(5)), at(0)).unwrap();
        table.insert("b".into(), Entry(at(100)), at(0)).unwrap();
        assert_eq!(
            table.insert("c".into(), Entry(at(100)), at(5)),
            Ok(()),
            "a has expired by t=5"
        );
        assert!(!table.contains_key("a"));
        assert!(table.contains_key("b") && table.contains_key("c"));
    }

    fn at_ms(milliseconds: i64) -> DateTime<Utc> {
        DateTime::from_timestamp_millis(1_800_000_000_000 + milliseconds).unwrap()
    }

    #[test]
    fn sweeps_run_at_most_once_a_second() {
        let mut table = ExpiringTable::new(1);
        table
            .insert("a".into(), Entry(at_ms(9_500)), at_ms(9_000))
            .unwrap();
        // The insert at 9.0 s swept. At 9.6 s a has expired, but no sweep is due.
        assert!(!table.has_room(at_ms(9_600)));
        assert_eq!(
            table.insert("b".into(), Entry(at_ms(20_000)), at_ms(9_600)),
            Err(TableFull)
        );
        // One second after the last sweep, the slot is reclaimed.
        assert!(table.has_room(at_ms(10_000)));
        assert_eq!(
            table.insert("b".into(), Entry(at_ms(20_000)), at_ms(10_000)),
            Ok(())
        );
    }

    #[test]
    fn a_clock_that_goes_back_sweeps_again() {
        let mut table = ExpiringTable::new(1);
        // Inserted at t=100 (just after that sweep) with an expiry of t=5.
        table.insert("a".into(), Entry(at(5)), at(100)).unwrap();
        assert!(table.contains_key("a"));
        // At t=50 the clock has gone back 50 s: no interval has passed since
        // t=100, but an earlier time always sweeps.
        assert!(table.has_room(at(50)));
        assert!(!table.contains_key("a"));
    }

    #[test]
    fn a_removed_entry_frees_its_slot_at_once() {
        let mut table = ExpiringTable::new(1);
        table.insert("a".into(), Entry(at(100)), at(0)).unwrap();
        assert!(table.remove("a").is_some());
        assert!(table.remove("a").is_none());
        assert_eq!(table.insert("b".into(), Entry(at(100)), at(0)), Ok(()));
    }
}
