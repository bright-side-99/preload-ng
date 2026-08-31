#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::{path::PathBuf, time::Duration};

/// Retention policy for pruning stale exes/maps from in-memory stores (and thus the DB).
///
/// Age values use **model time** (seconds the daemon has been running), not wall-clock.
/// A value of `0` disables that rule.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Persistence {
    /// Optional path to the state database.
    pub state_path: Option<PathBuf>,

    /// Autosave interval (overrides System.autosave when set).
    #[serde_as(as = "Option<serde_with::DurationSeconds>")]
    pub autosave_interval: Option<Duration>,

    pub save_on_shutdown: bool,

    /// Drop an exe if not seen for this long. `0` disables. Default: 30 days.
    #[serde_as(as = "serde_with::DurationSeconds")]
    pub exe_max_age: Duration,

    /// Drop a map if not re-observed for this long. `0` disables. Default: 14 days.
    #[serde_as(as = "serde_with::DurationSeconds")]
    pub map_max_age: Duration,

    /// After age prune, if exe count still exceeds this, drop oldest idle exes. `0` disables.
    pub max_exes: usize,

    /// After age prune, if map count still exceeds this, drop oldest maps. `0` disables.
    pub max_maps: usize,

    /// Also drop maps whose path no longer exists on disk.
    pub drop_missing_files: bool,

    /// Run SQLite `VACUUM` after a save that followed a prune with removals.
    pub vacuum_after_prune: bool,
}

impl Default for Persistence {
    fn default() -> Self {
        Self {
            state_path: None,
            autosave_interval: None,
            save_on_shutdown: true,
            exe_max_age: Duration::from_secs(30 * 24 * 60 * 60), // 30 days
            map_max_age: Duration::from_secs(14 * 24 * 60 * 60), // 14 days
            max_exes: 8192,
            max_maps: 65536,
            drop_missing_files: true,
            vacuum_after_prune: true,
        }
    }
}

impl Persistence {}
