#![forbid(unsafe_code)]

use config::Config;
use orchestrator::{
    ModelUpdater,
    domain::MapSegment,
    observation::{DefaultAdmissionPolicy, DefaultModelUpdater, ObservationEvent},
    stores::Stores,
};
use std::path::Path;
use std::sync::Arc;

#[test]
fn admits_exe_and_maps() {
    let config = Config::default();
    let policy = DefaultAdmissionPolicy::new(&config);
    let mut updater = DefaultModelUpdater::new(&config);
    let mut stores = Stores::default();

    let exe_path: Arc<Path> = Arc::from(Path::new("/usr/bin/app"));
    let map = MapSegment::from_arc(Arc::from(Path::new("/usr/lib/libfoo.so")), 0, config.model.minsize, 0);

    let observation = vec![
        ObservationEvent::ObsBegin {
            time: 0,
            scan_id: 1,
        },
        ObservationEvent::ExeSeen {
            path: exe_path.clone(),
            pid: 1,
        },
        ObservationEvent::MapSeen {
            exe_path: exe_path.clone(),
            map,
        },
        ObservationEvent::ObsEnd {
            time: 0,
            scan_id: 1,
            warnings: Vec::new(),
        },
    ];

    let delta = updater.apply(&mut stores, &observation, &policy).unwrap();

    assert_eq!(delta.new_exes.len(), 1, "delta: {:?}", delta);
    assert_eq!(delta.new_maps.len(), 1, "delta: {:?}", delta);
    assert_eq!(stores.exes.iter().count(), 1);
    assert_eq!(stores.maps.iter().count(), 1);
}

#[test]
fn refreshes_map_update_time_on_reobserve() {
    let config = Config::default();
    let policy = DefaultAdmissionPolicy::new(&config);
    let mut updater = DefaultModelUpdater::new(&config);
    let mut stores = Stores::default();

    let exe_path: Arc<Path> = Arc::from(Path::new("/usr/bin/app"));
    let map_path: Arc<Path> = Arc::from(Path::new("/usr/lib/libfoo.so"));

    let first = vec![
        ObservationEvent::ObsBegin {
            time: 10,
            scan_id: 1,
        },
        ObservationEvent::ExeSeen {
            path: exe_path.clone(),
            pid: 1,
        },
        ObservationEvent::MapSeen {
            exe_path: exe_path.clone(),
            map: MapSegment::from_arc(map_path.clone(), 0, config.model.minsize, 10),
        },
        ObservationEvent::ObsEnd {
            time: 10,
            scan_id: 1,
            warnings: Vec::new(),
        },
    ];
    updater.apply(&mut stores, &first, &policy).unwrap();

    let map_id = stores.maps.iter().next().unwrap().0;
    assert_eq!(stores.maps.get(map_id).unwrap().update_time, 10);

    let second = vec![
        ObservationEvent::ObsBegin {
            time: 500,
            scan_id: 2,
        },
        ObservationEvent::ExeSeen {
            path: exe_path.clone(),
            pid: 1,
        },
        ObservationEvent::MapSeen {
            exe_path: exe_path.clone(),
            map: MapSegment::from_arc(map_path.clone(), 0, config.model.minsize, 500),
        },
        ObservationEvent::ObsEnd {
            time: 500,
            scan_id: 2,
            warnings: Vec::new(),
        },
    ];
    let delta = updater.apply(&mut stores, &second, &policy).unwrap();
    assert!(delta.new_maps.is_empty());
    assert_eq!(stores.maps.get(map_id).unwrap().update_time, 500);
}
