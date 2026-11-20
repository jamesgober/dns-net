//! The answer cache: positive and negative answers keyed by question, kept
//! no longer than their TTL (capped), within a byte budget.
//!
//! Only whole answers to questions the resolver asked are stored, never the
//! other records a reply carried, so a reply cannot plant an entry for a
//! name it was not asked about. Eviction is CLOCK (second chance): a hit sets
//! a bit, and the sweep evicts the first entry without it, which keeps
//! frequently used names at the cost of one bit and no reordering on a hit.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::exchange::Status;
use crate::message::Record;
use crate::name::Name;
use crate::rdata::RData;
use crate::types::RecordType;

/// An answer as cached and as handed to callers.
#[derive(Debug)]
pub(crate) struct Entry {
    pub(crate) status: Status,
    pub(crate) records: Vec<Record>,
    pub(crate) chain: Vec<Record>,
}

/// Counters of the cache.
///
/// ```
/// let s = dns_net::CacheStats::default();
/// assert_eq!(s.hits, 0);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CacheStats {
    /// Entries held now.
    pub entries: usize,
    /// Their estimated size in bytes.
    pub bytes: usize,
    /// Lookups answered from the cache.
    pub hits: u64,
    /// Lookups that found no live entry.
    pub misses: u64,
    /// Entries stored.
    pub inserts: u64,
    /// Entries removed to make room.
    pub evictions: u64,
}

type Key = (Name, RecordType);

struct Slot {
    key: Key,
    entry: Arc<Entry>,
    expires: Instant,
    size: usize,
    referenced: bool,
}

pub(crate) struct Cache {
    map: HashMap<Key, usize>,
    slots: Vec<Option<Slot>>,
    free: Vec<usize>,
    hand: usize,
    budget: usize,
    max_ttl: u32,
    max_negative_ttl: u32,
    stats: CacheStats,
}

/// Fixed cost per entry: the slot, the map's share, the `Arc`, the vectors.
const ENTRY_OVERHEAD: usize = 160;
/// Per record: the `Record` itself and its heap pieces' headers.
const RECORD_OVERHEAD: usize = 96;

impl Cache {
    pub(crate) fn new(budget: usize, max_ttl: u32, max_negative_ttl: u32) -> Cache {
        Cache {
            map: HashMap::new(),
            slots: Vec::new(),
            free: Vec::new(),
            hand: 0,
            budget,
            max_ttl,
            max_negative_ttl,
            stats: CacheStats::default(),
        }
    }

    /// The live entry for the question and when it expires.
    pub(crate) fn get(
        &mut self,
        name: &Name,
        rtype: RecordType,
        now: Instant,
    ) -> Option<(Arc<Entry>, Instant)> {
        let key = (name.clone(), rtype);
        let Some(&i) = self.map.get(&key) else {
            self.stats.misses += 1;
            return None;
        };
        let live = self.slots[i].as_ref().is_some_and(|s| s.expires > now);
        if !live {
            self.remove(i);
            self.stats.misses += 1;
            return None;
        }
        let slot = self.slots[i].as_mut()?;
        slot.referenced = true;
        self.stats.hits += 1;
        Some((Arc::clone(&slot.entry), slot.expires))
    }

    /// Stores `entry` for `ttl` seconds (capped); returns when it expires, or
    /// `None` when it was not stored (a TTL of 0, an uncacheable negative
    /// answer, or larger than an eighth of the budget).
    pub(crate) fn insert(
        &mut self,
        name: &Name,
        rtype: RecordType,
        entry: Arc<Entry>,
        ttl: Option<u32>,
        now: Instant,
    ) -> Option<Instant> {
        let cap = if entry.status == Status::Found {
            self.max_ttl
        } else {
            self.max_negative_ttl
        };
        let ttl = ttl?.min(cap);
        if ttl == 0 {
            return None;
        }
        let size = estimate(name, &entry);
        if size > self.budget / 8 {
            return None;
        }
        let key = (name.to_lowercase(), rtype);
        if let Some(&i) = self.map.get(&key) {
            self.remove(i);
        }
        while self.stats.bytes + size > self.budget {
            if !self.evict_one(now) {
                return None;
            }
        }
        let expires = now + Duration::from_secs(u64::from(ttl));
        let slot = Slot {
            key: key.clone(),
            entry,
            expires,
            size,
            referenced: false,
        };
        let i = match self.free.pop() {
            Some(i) => {
                self.slots[i] = Some(slot);
                i
            }
            None => {
                self.slots.push(Some(slot));
                self.slots.len() - 1
            }
        };
        self.map.insert(key, i);
        self.stats.bytes += size;
        self.stats.entries += 1;
        self.stats.inserts += 1;
        Some(expires)
    }

    /// One turn of the CLOCK hand: evicts an expired or unreferenced entry,
    /// giving referenced ones a second chance. False when the cache is empty.
    fn evict_one(&mut self, now: Instant) -> bool {
        if self.stats.entries == 0 {
            return false;
        }
        // Two passes clear every bit, so the loop ends within them.
        for _ in 0..2 * self.slots.len() {
            let i = self.hand;
            self.hand = (self.hand + 1) % self.slots.len();
            let Some(slot) = self.slots[i].as_mut() else {
                continue;
            };
            if slot.referenced && slot.expires > now {
                slot.referenced = false;
                continue;
            }
            self.remove(i);
            self.stats.evictions += 1;
            return true;
        }
        false
    }

    fn remove(&mut self, i: usize) {
        if let Some(slot) = self.slots[i].take() {
            self.map.remove(&slot.key);
            self.stats.bytes -= slot.size;
            self.stats.entries -= 1;
            self.free.push(i);
        }
    }

    pub(crate) fn clear(&mut self) {
        self.map.clear();
        self.slots.clear();
        self.free.clear();
        self.hand = 0;
        self.stats.bytes = 0;
        self.stats.entries = 0;
    }

    pub(crate) fn stats(&self) -> CacheStats {
        self.stats
    }
}

fn estimate(name: &Name, entry: &Entry) -> usize {
    let record = |r: &Record| {
        RECORD_OVERHEAD
            + r.name.wire_len()
            + match &r.data {
                RData::A(_) => 4,
                RData::Aaaa(_) => 16,
                RData::Ns(n) | RData::Cname(n) | RData::Ptr(n) => n.wire_len(),
                RData::Soa { mname, rname, .. } => mname.wire_len() + rname.wire_len() + 20,
                RData::Mx { exchange, .. } => exchange.wire_len() + 2,
                RData::Txt(s) => s.iter().map(|s| s.len() + 16).sum(),
                RData::Srv { target, .. } => target.wire_len() + 6,
                RData::Caa { tag, value, .. } => tag.len() + value.len() + 32,
                RData::Unknown { data, .. } => data.len() + 16,
            }
    };
    ENTRY_OVERHEAD
        + name.wire_len()
        + entry.records.iter().map(record).sum::<usize>()
        + entry.chain.iter().map(record).sum::<usize>()
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn n(s: &str) -> Name {
        Name::parse(s).unwrap()
    }

    fn found(last: u8) -> Arc<Entry> {
        Arc::new(Entry {
            status: Status::Found,
            records: vec![Record::new(
                n("x.example"),
                60,
                RData::A(Ipv4Addr::new(192, 0, 2, last)),
            )],
            chain: Vec::new(),
        })
    }

    fn negative() -> Arc<Entry> {
        Arc::new(Entry {
            status: Status::NxDomain,
            records: Vec::new(),
            chain: Vec::new(),
        })
    }

    #[test]
    fn hits_until_expiry_and_case_is_ignored() {
        let now = Instant::now();
        let mut c = Cache::new(1 << 20, 86_400, 900);
        assert!(
            c.insert(&n("X.Example"), RecordType::A, found(1), Some(30), now)
                .is_some()
        );
        assert!(c.get(&n("x.example"), RecordType::A, now).is_some());
        assert!(c.get(&n("x.example"), RecordType::AAAA, now).is_none());
        let later = now + Duration::from_secs(30);
        assert!(c.get(&n("x.example"), RecordType::A, later).is_none());
        let s = c.stats();
        assert_eq!((s.hits, s.misses, s.entries), (1, 2, 0));
    }

    #[test]
    fn ttl_caps_and_refusals() {
        let now = Instant::now();
        let mut c = Cache::new(1 << 20, 100, 10);
        let e = c
            .insert(&n("a"), RecordType::A, found(1), Some(1_000_000), now)
            .unwrap();
        assert_eq!(e - now, Duration::from_secs(100));
        let e = c
            .insert(&n("b"), RecordType::A, negative(), Some(3600), now)
            .unwrap();
        assert_eq!(e - now, Duration::from_secs(10));
        assert!(
            c.insert(&n("c"), RecordType::A, found(1), Some(0), now)
                .is_none()
        );
        assert!(
            c.insert(&n("d"), RecordType::A, negative(), None, now)
                .is_none()
        );
        let mut tiny = Cache::new(1000, 100, 10);
        assert!(
            tiny.insert(&n("e"), RecordType::A, found(1), Some(5), now)
                .is_none()
        );
    }

    #[test]
    fn budget_holds_and_hot_entries_survive() {
        let now = Instant::now();
        let one = estimate(&n("name00.example"), &found(1));
        let mut c = Cache::new(one * 10, 86_400, 900);
        for i in 0..10 {
            let name = n(&format!("name{i:02}.example"));
            assert!(
                c.insert(&name, RecordType::A, found(1), Some(60), now)
                    .is_some()
            );
        }
        assert_eq!(c.stats().entries, 10);
        // name3 is used, then ten more arrive.
        assert!(c.get(&n("name03.example"), RecordType::A, now).is_some());
        for i in 10..19 {
            let name = n(&format!("name{i:02}.example"));
            assert!(
                c.insert(&name, RecordType::A, found(1), Some(60), now)
                    .is_some()
            );
            assert!(c.stats().bytes <= one * 10);
        }
        assert!(c.get(&n("name03.example"), RecordType::A, now).is_some());
        assert!(c.get(&n("name00.example"), RecordType::A, now).is_none());
        assert!(c.stats().evictions >= 9);
        // Replacing an entry does not grow the cache.
        let before = c.stats();
        assert!(
            c.insert(&n("NAME03.example"), RecordType::A, found(2), Some(60), now)
                .is_some()
        );
        assert_eq!(c.stats().entries, before.entries);
        let (e, _) = c.get(&n("name03.example"), RecordType::A, now).unwrap();
        assert_eq!(e.records[0].data, RData::A(Ipv4Addr::new(192, 0, 2, 2)));
        c.clear();
        assert_eq!(c.stats().entries, 0);
        assert_eq!(c.stats().bytes, 0);
    }
}
