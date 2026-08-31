#![forbid(unsafe_code)]

mod active_set;
mod edge_key;
mod exe_map_index;
mod exe_store;
mod map_store;
mod markov_graph;

pub use active_set::ActiveSet;
pub use edge_key::EdgeKey;
pub use exe_map_index::ExeMapIndex;
pub use exe_store::ExeStore;
pub use map_store::MapStore;
pub use markov_graph::{EdgeRef, EdgeRefMut, MarkovGraph};

use crate::domain::{ExeId, ExeKey, MapId, MapSegment, MarkovState};
use rustc_hash::FxHashSet;
use std::time::Duration;

/// Policy controlling automatic pruning of stale exes and maps.
///
/// Age values are in **model time** (seconds). A value of `0` disables that rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrunePolicy {
    pub exe_max_age: Duration,
    pub map_max_age: Duration,
    pub max_exes: usize,
    pub max_maps: usize,
    pub drop_missing_files: bool,
}

impl Default for PrunePolicy {
    fn default() -> Self {
        Self {
            exe_max_age: Duration::from_secs(30 * 24 * 60 * 60),
            map_max_age: Duration::from_secs(14 * 24 * 60 * 60),
            max_exes: 8192,
            max_maps: 65536,
            drop_missing_files: true,
        }
    }
}

impl From<&config::Persistence> for PrunePolicy {
    fn from(p: &config::Persistence) -> Self {
        Self {
            exe_max_age: p.exe_max_age,
            map_max_age: p.map_max_age,
            max_exes: p.max_exes,
            max_maps: p.max_maps,
            drop_missing_files: p.drop_missing_files,
        }
    }
}

/// Counts of entries removed by a prune pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PruneReport {
    pub exes_removed: usize,
    pub maps_removed: usize,
    pub edges_removed: usize,
}

impl PruneReport {
    pub fn any_removed(&self) -> bool {
        self.exes_removed > 0 || self.maps_removed > 0 || self.edges_removed > 0
    }
}

#[derive(Debug, Default)]
pub struct Stores {
    pub exes: ExeStore,
    pub maps: MapStore,
    pub exe_maps: ExeMapIndex,
    pub markov: MarkovGraph,
    pub active: ActiveSet,
    pub model_time: u64,
    pub last_accounting_time: u64,
}

impl Stores {
    pub fn ensure_exe(&mut self, key: ExeKey) -> ExeId {
        self.exes.ensure(key)
    }

    pub fn ensure_map(&mut self, segment: MapSegment) -> MapId {
        self.maps.ensure(segment)
    }

    pub fn ensure_map_with_flag(&mut self, segment: MapSegment) -> (MapId, bool) {
        self.maps.ensure_with_flag(segment)
    }

    pub fn attach_map(&mut self, exe_id: ExeId, map_id: MapId) {
        self.exe_maps.attach(exe_id, map_id);
    }

    pub fn ensure_markov_edge(&mut self, a: ExeId, b: ExeId, now: u64, state: MarkovState) -> bool {
        self.markov.ensure_edge(a, b, now, state)
    }

    pub fn remove_map_by_key(&mut self, key: &crate::domain::MapKey) {
        if let Some(id) = self.maps.id_by_key(key) {
            self.exe_maps.detach_map(id);
            self.maps.remove(id);
        }
    }

    pub fn remove_exe(&mut self, exe_id: ExeId) {
        self.active.remove(exe_id);
        self.exe_maps.remove_exe(exe_id);
        self.exes.remove(exe_id);
    }

    pub fn remove_map(&mut self, map_id: MapId) {
        self.exe_maps.detach_map(map_id);
        self.maps.remove(map_id);
    }

    pub fn active_exes(&self) -> FxHashSet<ExeId> {
        self.active.exes()
    }

    /// Prune stale executables and maps according to `policy`.
    ///
    /// Uses `now` as the current model time. Never drops a currently-running
    /// executable, or (during the count-cap pass) a map attached only to a
    /// running executable.
    pub fn prune(&mut self, policy: &PrunePolicy, now: u64) -> PruneReport {
        let mut report = PruneReport::default();

        // --- Exe age prune ---
        let exe_max_age_secs = policy.exe_max_age.as_secs();
        let mut exes_to_drop: Vec<ExeId> = Vec::new();

        if exe_max_age_secs > 0 {
            for (id, exe) in self.exes.iter() {
                if exe.running {
                    continue;
                }
                let stale = match exe.last_seen_time {
                    None => true,
                    Some(last) => now.saturating_sub(last) > exe_max_age_secs,
                };
                if stale {
                    exes_to_drop.push(id);
                }
            }
        }

        for id in exes_to_drop {
            self.remove_exe(id);
            report.exes_removed += 1;
        }

        // --- Exe count cap ---
        if policy.max_exes > 0 && self.exes.len() > policy.max_exes {
            let mut candidates: Vec<(ExeId, u64)> = self
                .exes
                .iter()
                .filter(|(_, exe)| !exe.running)
                .map(|(id, exe)| (id, exe.last_seen_time.unwrap_or(0)))
                .collect();
            // Oldest first (smallest last_seen).
            candidates.sort_by_key(|(_, last)| *last);

            let excess = self.exes.len().saturating_sub(policy.max_exes);
            for (id, _) in candidates.into_iter().take(excess) {
                self.remove_exe(id);
                report.exes_removed += 1;
            }
        }

        // --- Markov edges for removed exes ---
        let remaining_exes: FxHashSet<ExeId> = self.exes.iter().map(|(id, _)| id).collect();
        let edges_before = self.markov.len();
        self.markov.prune_inactive(&remaining_exes);
        report.edges_removed = edges_before.saturating_sub(self.markov.len());

        // --- Map age / orphan / missing-file prune ---
        let map_max_age_secs = policy.map_max_age.as_secs();
        let mut maps_to_drop: Vec<MapId> = Vec::new();

        for (id, map) in self.maps.iter() {
            let orphan = self.exe_maps.exes_for_map(id).next().is_none();
            let aged =
                map_max_age_secs > 0 && now.saturating_sub(map.update_time) > map_max_age_secs;
            let missing = policy.drop_missing_files && !map.path.exists();
            if orphan || aged || missing {
                maps_to_drop.push(id);
            }
        }

        for id in maps_to_drop {
            self.remove_map(id);
            report.maps_removed += 1;
        }

        // --- Map count cap ---
        if policy.max_maps > 0 && self.maps.len() > policy.max_maps {
            let running_exes: FxHashSet<ExeId> = self
                .exes
                .iter()
                .filter(|(_, exe)| exe.running)
                .map(|(id, _)| id)
                .collect();

            let mut candidates: Vec<(MapId, u64)> = self
                .maps
                .iter()
                .filter(|(id, _)| {
                    // Keep maps attached to a running exe.
                    !self
                        .exe_maps
                        .exes_for_map(*id)
                        .any(|exe_id| running_exes.contains(&exe_id))
                })
                .map(|(id, map)| (id, map.update_time))
                .collect();
            candidates.sort_by_key(|(_, t)| *t);

            let excess = self.maps.len().saturating_sub(policy.max_maps);
            for (id, _) in candidates.into_iter().take(excess) {
                self.remove_map(id);
                report.maps_removed += 1;
            }
        }

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{ExeKey, MapSegment};
    use std::path::PathBuf;
    use std::sync::Arc;
    use tempfile::NamedTempFile;

    fn make_exe(stores: &mut Stores, path: &str, last_seen: Option<u64>, running: bool) -> ExeId {
        let id = stores.ensure_exe(ExeKey::new(PathBuf::from(path)));
        if let Some(exe) = stores.exes.get_mut(id) {
            exe.last_seen_time = last_seen;
            exe.running = running;
        }
        id
    }

    fn make_map(stores: &mut Stores, path: &str, update_time: u64) -> MapId {
        stores.ensure_map(MapSegment::new(path, 0, 4096, update_time))
    }

    #[test]
    fn drops_stale_exe_keeps_running() {
        let mut stores = Stores {
            model_time: 1000,
            ..Default::default()
        };
        make_exe(&mut stores, "/bin/old", Some(1), false);
        make_exe(&mut stores, "/bin/run", Some(1), true);
        make_exe(&mut stores, "/bin/recent", Some(900), false);

        let policy = PrunePolicy {
            exe_max_age: Duration::from_secs(100),
            map_max_age: Duration::from_secs(0),
            max_exes: 0,
            max_maps: 0,
            drop_missing_files: false,
        };
        let report = stores.prune(&policy, 1000);

        assert_eq!(report.exes_removed, 1);
        assert_eq!(stores.exes.len(), 2);
        assert!(stores.exes.id_by_key(&ExeKey::new("/bin/run")).is_some());
        assert!(stores.exes.id_by_key(&ExeKey::new("/bin/recent")).is_some());
        assert!(stores.exes.id_by_key(&ExeKey::new("/bin/old")).is_none());
    }

    #[test]
    fn drops_exe_with_no_last_seen() {
        let mut stores = Stores {
            model_time: 100,
            ..Default::default()
        };
        make_exe(&mut stores, "/bin/never", None, false);

        let policy = PrunePolicy {
            exe_max_age: Duration::from_secs(1),
            map_max_age: Duration::from_secs(0),
            max_exes: 0,
            max_maps: 0,
            drop_missing_files: false,
        };
        let report = stores.prune(&policy, 100);
        assert_eq!(report.exes_removed, 1);
        assert_eq!(stores.exes.len(), 0);
    }

    #[test]
    fn zero_age_disables_exe_prune() {
        let mut stores = Stores {
            model_time: 1_000_000,
            ..Default::default()
        };
        make_exe(&mut stores, "/bin/old", Some(1), false);

        let policy = PrunePolicy {
            exe_max_age: Duration::from_secs(0),
            map_max_age: Duration::from_secs(0),
            max_exes: 0,
            max_maps: 0,
            drop_missing_files: false,
        };
        let report = stores.prune(&policy, 1_000_000);
        assert_eq!(report.exes_removed, 0);
        assert_eq!(stores.exes.len(), 1);
    }

    #[test]
    fn drops_orphan_maps_after_exe_prune() {
        let mut stores = Stores {
            model_time: 1000,
            ..Default::default()
        };
        let exe = make_exe(&mut stores, "/bin/old", Some(1), false);
        let map = make_map(&mut stores, "/lib/old.so", 500);
        stores.attach_map(exe, map);

        let policy = PrunePolicy {
            exe_max_age: Duration::from_secs(100),
            map_max_age: Duration::from_secs(0),
            max_exes: 0,
            max_maps: 0,
            drop_missing_files: false,
        };
        let report = stores.prune(&policy, 1000);
        assert_eq!(report.exes_removed, 1);
        assert_eq!(report.maps_removed, 1);
        assert_eq!(stores.maps.len(), 0);
    }

    #[test]
    fn drops_aged_maps() {
        let mut stores = Stores {
            model_time: 1000,
            ..Default::default()
        };
        let exe = make_exe(&mut stores, "/bin/app", Some(900), false);
        let old_map = make_map(&mut stores, "/lib/old.so", 1);
        let new_map = make_map(&mut stores, "/lib/new.so", 950);
        stores.attach_map(exe, old_map);
        stores.attach_map(exe, new_map);

        let policy = PrunePolicy {
            exe_max_age: Duration::from_secs(0),
            map_max_age: Duration::from_secs(100),
            max_exes: 0,
            max_maps: 0,
            drop_missing_files: false,
        };
        let report = stores.prune(&policy, 1000);
        assert_eq!(report.maps_removed, 1);
        assert_eq!(stores.maps.len(), 1);
        assert!(
            stores
                .maps
                .id_by_key(&crate::domain::MapKey::new("/lib/new.so", 0, 4096))
                .is_some()
        );
    }

    #[test]
    fn drops_missing_files_when_enabled() {
        let tmp = NamedTempFile::new().unwrap();
        let existing = tmp.path().to_path_buf();
        let missing = PathBuf::from("/tmp/preload-ng-definitely-missing-map-xyz");

        let mut stores = Stores::default();
        let exe = make_exe(&mut stores, "/bin/app", Some(0), false);
        let keep = stores.ensure_map(MapSegment::from_arc(
            Arc::from(existing.as_path()),
            0,
            4096,
            0,
        ));
        let drop_id = stores.ensure_map(MapSegment::from_arc(
            Arc::from(missing.as_path()),
            0,
            4096,
            0,
        ));
        stores.attach_map(exe, keep);
        stores.attach_map(exe, drop_id);

        let policy = PrunePolicy {
            exe_max_age: Duration::from_secs(0),
            map_max_age: Duration::from_secs(0),
            max_exes: 0,
            max_maps: 0,
            drop_missing_files: true,
        };
        let report = stores.prune(&policy, 0);
        assert_eq!(report.maps_removed, 1);
        assert_eq!(stores.maps.len(), 1);
    }

    #[test]
    fn count_cap_drops_oldest_idle_exes() {
        let mut stores = Stores {
            model_time: 100,
            ..Default::default()
        };
        make_exe(&mut stores, "/bin/a", Some(10), false);
        make_exe(&mut stores, "/bin/b", Some(20), false);
        make_exe(&mut stores, "/bin/c", Some(30), false);
        make_exe(&mut stores, "/bin/run", Some(5), true);

        let policy = PrunePolicy {
            exe_max_age: Duration::from_secs(0),
            map_max_age: Duration::from_secs(0),
            max_exes: 2,
            max_maps: 0,
            drop_missing_files: false,
        };
        let report = stores.prune(&policy, 100);
        // 4 exes, max 2 → drop 2 oldest idle (a,b). Running exe kept.
        assert_eq!(report.exes_removed, 2);
        assert_eq!(stores.exes.len(), 2);
        assert!(stores.exes.id_by_key(&ExeKey::new("/bin/run")).is_some());
        assert!(stores.exes.id_by_key(&ExeKey::new("/bin/c")).is_some());
    }

    #[test]
    fn prunes_markov_edges_for_removed_exes() {
        let mut stores = Stores {
            model_time: 1000,
            ..Default::default()
        };
        let a = make_exe(&mut stores, "/bin/a", Some(1), false);
        let b = make_exe(&mut stores, "/bin/b", Some(900), false);
        stores.ensure_markov_edge(a, b, 0, MarkovState::Neither);
        assert_eq!(stores.markov.len(), 1);

        let policy = PrunePolicy {
            exe_max_age: Duration::from_secs(100),
            map_max_age: Duration::from_secs(0),
            max_exes: 0,
            max_maps: 0,
            drop_missing_files: false,
        };
        let report = stores.prune(&policy, 1000);
        assert_eq!(report.exes_removed, 1);
        assert_eq!(report.edges_removed, 1);
        assert_eq!(stores.markov.len(), 0);
    }
}
