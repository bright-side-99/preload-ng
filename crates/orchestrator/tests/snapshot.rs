#![forbid(unsafe_code)]

use orchestrator::StateRepository;
use orchestrator::domain::MapKey;
use orchestrator::persistence::{
    ExeMapRecord, ExeRecord, MapRecord, MarkovRecord, SNAPSHOT_SCHEMA_VERSION, SnapshotMeta,
    SqliteRepository, StateSnapshot, StoresSnapshot,
};
use std::path::PathBuf;
use tempfile::tempdir;

#[tokio::test]
async fn sqlite_roundtrip_snapshot() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("state.db");

    let snapshot = StoresSnapshot {
        meta: SnapshotMeta {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            app_version: Some("test".into()),
            created_at: None,
        },
        state: StateSnapshot {
            model_time: 10,
            last_accounting_time: 5,
            exes: vec![ExeRecord {
                path: PathBuf::from("/usr/bin/app"),
                total_running_time: 42,
                last_seen_time: Some(9),
            }],
            maps: vec![MapRecord {
                path: PathBuf::from("/usr/lib/libfoo.so"),
                offset: 0,
                length: 4096,
                update_time: 10,
            }],
            exe_maps: vec![ExeMapRecord {
                exe_path: PathBuf::from("/usr/bin/app"),
                map_key: MapKey::new(PathBuf::from("/usr/lib/libfoo.so"), 0, 4096),
                prob: 1.0,
            }],
            markov_edges: vec![MarkovRecord {
                exe_a: PathBuf::from("/usr/bin/app"),
                exe_b: PathBuf::from("/usr/bin/app2"),
                time_to_leave: [0.0; 4],
                transition_prob: [[0.0; 4]; 4],
                both_running_time: 0,
            }],
        },
    };

    let repo = SqliteRepository::new(db_path).await.unwrap();
    repo.save(&snapshot).await.unwrap();
    let loaded = repo.load().await.unwrap();

    assert_eq!(loaded.state.exes.len(), 1);
    assert_eq!(loaded.state.maps.len(), 1);
    assert_eq!(loaded.state.exe_maps.len(), 1);
    assert_eq!(loaded.state.markov_edges.len(), 1);
    assert_eq!(loaded.state.model_time, 10);
}

#[tokio::test]
async fn pruned_state_does_not_roundtrip_removed_rows() {
    use orchestrator::{
        domain::{ExeKey, MapSegment, MarkovState},
        stores::{PrunePolicy, Stores},
    };
    use std::time::Duration;

    let mut stores = Stores {
        model_time: 10_000,
        last_accounting_time: 10_000,
        ..Default::default()
    };
    let keep = stores.ensure_exe(ExeKey::new("/usr/bin/keep"));
    if let Some(exe) = stores.exes.get_mut(keep) {
        exe.last_seen_time = Some(9_900);
    }
    let drop_exe = stores.ensure_exe(ExeKey::new("/usr/bin/stale"));
    if let Some(exe) = stores.exes.get_mut(drop_exe) {
        exe.last_seen_time = Some(1);
    }
    let keep_map = stores.ensure_map(MapSegment::new("/usr/lib/keep.so", 0, 4096, 9_900));
    let drop_map = stores.ensure_map(MapSegment::new("/usr/lib/stale.so", 0, 4096, 1));
    stores.attach_map(keep, keep_map);
    stores.attach_map(drop_exe, drop_map);
    stores.ensure_markov_edge(keep, drop_exe, 0, MarkovState::Neither);

    let policy = PrunePolicy {
        exe_max_age: Duration::from_secs(100),
        map_max_age: Duration::from_secs(100),
        max_exes: 0,
        max_maps: 0,
        drop_missing_files: false,
    };
    let report = stores.prune(&policy, stores.model_time);
    assert!(report.exes_removed >= 1);
    assert!(report.maps_removed >= 1);

    let snapshot = {
        use orchestrator::persistence::{
            ExeMapRecord, ExeRecord, MapRecord, MarkovRecord, SNAPSHOT_SCHEMA_VERSION,
            SnapshotMeta, StateSnapshot, StoresSnapshot,
        };
        let mut exes = Vec::new();
        for (_, exe) in stores.exes.iter() {
            exes.push(ExeRecord {
                path: exe.key.path().to_path_buf(),
                total_running_time: exe.total_running_time,
                last_seen_time: exe.last_seen_time,
            });
        }
        let mut maps = Vec::new();
        for (_, map) in stores.maps.iter() {
            maps.push(MapRecord {
                path: map.path.to_path_buf(),
                offset: map.offset,
                length: map.length,
                update_time: map.update_time,
            });
        }
        let mut exe_maps = Vec::new();
        for (exe_id, exe) in stores.exes.iter() {
            for map_id in stores.exe_maps.maps_for_exe(exe_id) {
                if let Some(map) = stores.maps.get(map_id) {
                    exe_maps.push(ExeMapRecord {
                        exe_path: exe.key.path().to_path_buf(),
                        map_key: map.key(),
                        prob: 1.0,
                    });
                }
            }
        }
        let mut markov_edges = Vec::new();
        for (key, edge) in stores.markov.iter() {
            let Some(exe_a) = stores.exes.get(key.a()) else {
                continue;
            };
            let Some(exe_b) = stores.exes.get(key.b()) else {
                continue;
            };
            markov_edges.push(MarkovRecord {
                exe_a: exe_a.key.path().to_path_buf(),
                exe_b: exe_b.key.path().to_path_buf(),
                time_to_leave: edge.time_to_leave_f32(),
                transition_prob: edge.transition_prob_f32(),
                both_running_time: edge.both_running_time,
            });
        }
        StoresSnapshot {
            meta: SnapshotMeta {
                schema_version: SNAPSHOT_SCHEMA_VERSION,
                app_version: None,
                created_at: None,
            },
            state: StateSnapshot {
                model_time: stores.model_time,
                last_accounting_time: stores.last_accounting_time,
                exes,
                maps,
                exe_maps,
                markov_edges,
            },
        }
    };

    let dir = tempdir().unwrap();
    let db_path = dir.path().join("state.db");
    let repo = SqliteRepository::new(db_path).await.unwrap();
    repo.save_with_vacuum(&snapshot, true).await.unwrap();
    let loaded = repo.load().await.unwrap();

    assert_eq!(loaded.state.exes.len(), 1);
    assert_eq!(loaded.state.exes[0].path, PathBuf::from("/usr/bin/keep"));
    assert_eq!(loaded.state.maps.len(), 1);
    assert_eq!(loaded.state.maps[0].path, PathBuf::from("/usr/lib/keep.so"));
    assert!(loaded.state.markov_edges.is_empty());
}
