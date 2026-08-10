#![forbid(unsafe_code)]

use crate::domain::MapSegment;
use crate::observation::ObservationEvent;
use nix::sys::fanotify::{EventFFlags, Fanotify, InitFlags, MarkFlags, MaskFlags};
use rustc_hash::FxHashMap;
use std::collections::HashSet;
use std::os::fd::AsRawFd;
use std::os::linux::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use tracing::{info, trace, warn};

const SKIP_PREFIXES: &[&str] = &[
    "/proc/",
    "/sys/",
    "/dev/",
    "/tmp/",
    "/run/user/",
    "/run/lock/",
    "/run/credentials/",
    "/var/run/",
    "/var/lock/",
];

const VIRTUAL_FILESYSTEMS: &[&str] = &[
    "autofs",
    "bdev",
    "binfmt_misc",
    "bpf",
    "cgroup",
    "cgroup2",
    "configfs",
    "debugfs",
    "devpts",
    "devtmpfs",
    "efivarfs",
    "fuse.portal",
    "fusectl",
    "hugetlbfs",
    "mqueue",
    "nsfs",
    "pstore",
    "proc",
    "ramfs",
    "securityfs",
    "sysfs",
    "tmpfs",
    "tracefs",
];

fn is_virtual_filesystem(fs_type: &str) -> bool {
    VIRTUAL_FILESYSTEMS.contains(&fs_type)
}

/// Decode the octal escapes used for whitespace and backslashes in mountinfo.
fn decode_mount_path(path: &Path) -> PathBuf {
    let Some(raw) = path.to_str() else {
        return path.to_path_buf();
    };

    let bytes = raw.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\'
            && index + 3 < bytes.len()
            && (b'0'..=b'7').contains(&bytes[index + 1])
            && (b'0'..=b'7').contains(&bytes[index + 2])
            && (b'0'..=b'7').contains(&bytes[index + 3])
        {
            let value = (u16::from(bytes[index + 1] - b'0') * 64)
                + (u16::from(bytes[index + 2] - b'0') * 8)
                + u16::from(bytes[index + 3] - b'0');
            decoded.push(value as u8);
            index += 4;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }

    PathBuf::from(String::from_utf8_lossy(&decoded).into_owned())
}

#[derive(Debug, Clone, Copy)]
struct FileMeta {
    size: u64,
    device: u64,
    inode: u64,
}

#[derive(Default)]
struct EventBuffer {
    maps: FxHashMap<(Arc<Path>, Arc<Path>), FileMeta>,
    exes: FxHashMap<Arc<Path>, u32>,
}

pub struct FanotifyWatcher {
    buffer: Arc<Mutex<EventBuffer>>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl FanotifyWatcher {
    pub fn try_new() -> Option<Arc<Self>> {
        let fan = match Fanotify::init(
            InitFlags::FAN_CLOEXEC | InitFlags::FAN_CLASS_NOTIF | InitFlags::FAN_NONBLOCK,
            EventFFlags::O_RDONLY | EventFFlags::O_CLOEXEC | EventFFlags::O_LARGEFILE,
        ) {
            Ok(f) => f,
            Err(err) => {
                warn!(?err, "fanotify init failed (need CAP_SYS_ADMIN)");
                return None;
            }
        };

        let root = match std::fs::File::open("/") {
            Ok(f) => f,
            Err(err) => {
                warn!(?err, "failed to open / for fanotify mark");
                return None;
            }
        };

        if let Err(err) = fan.mark(
            MarkFlags::FAN_MARK_ADD | MarkFlags::FAN_MARK_FILESYSTEM,
            MaskFlags::FAN_OPEN,
            &root,
            None::<&std::path::Path>,
        ) {
            warn!(?err, "fanotify mark failed");
            return None;
        }

        Self::mark_mounted_filesystems(&fan);

        let buffer = Arc::new(Mutex::new(EventBuffer::default()));
        let stop = Arc::new(AtomicBool::new(false));

        let handle = {
            let buffer = Arc::clone(&buffer);
            let stop = Arc::clone(&stop);
            match std::thread::Builder::new()
                .name("fanotify-reader".into())
                .spawn(move || Self::reader_loop(fan, buffer, stop))
            {
                Ok(h) => h,
                Err(err) => {
                    warn!(?err, "failed to spawn fanotify reader thread");
                    return None;
                }
            }
        };

        info!("fanotify watcher started");
        Some(Arc::new(Self {
            buffer,
            stop,
            handle: Some(handle),
        }))
    }

    /// Mark each non-virtual filesystem in this process's mount namespace.
    ///
    /// FAN_MARK_FILESYSTEM on `/` does not follow mounts backed by a different
    /// filesystem, which would otherwise exclude common Steam libraries.
    fn mark_mounted_filesystems(fan: &Fanotify) {
        let mounts = match procfs::process::Process::myself()
            .and_then(|process| process.mountinfo())
        {
            Ok(mounts) => mounts,
            Err(err) => {
                warn!(?err, "failed to enumerate mountpoints for fanotify");
                return;
            }
        };

        let mut marked_devices = HashSet::new();
        let mut marked = 0u32;

        for mount in mounts {
            if is_virtual_filesystem(&mount.fs_type) {
                continue;
            }

            let mount_point = decode_mount_path(&mount.mount_point);
            if mount_point == Path::new("/") {
                marked_devices.insert(mount.majmin.clone());
                continue;
            }
            if marked_devices.contains(&mount.majmin) {
                continue;
            }

            let file = match std::fs::File::open(&mount_point) {
                Ok(file) => file,
                Err(err) => {
                    trace!(
                        ?err,
                        path = %mount_point.display(),
                        fs_type = %mount.fs_type,
                        "failed to open mountpoint for fanotify"
                    );
                    continue;
                }
            };

            match fan.mark(
                MarkFlags::FAN_MARK_ADD | MarkFlags::FAN_MARK_FILESYSTEM,
                MaskFlags::FAN_OPEN,
                &file,
                None::<&Path>,
            ) {
                Ok(()) => {
                    marked_devices.insert(mount.majmin.clone());
                    marked += 1;
                    trace!(
                        path = %mount_point.display(),
                        fs_type = %mount.fs_type,
                        "fanotify filesystem mark added"
                    );
                }
                Err(err) => {
                    trace!(
                        ?err,
                        path = %mount_point.display(),
                        fs_type = %mount.fs_type,
                        "failed to mark filesystem for fanotify"
                    );
                }
            }
        }

        info!(marked, "fanotify mounted filesystem marks added");
    }

    fn reader_loop(
        fan: Fanotify,
        buffer: Arc<Mutex<EventBuffer>>,
        stop: Arc<AtomicBool>,
    ) {
        use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
        use std::fmt::Write as FmtWrite;

        let self_pid = std::process::id() as i32;
        use std::os::fd::AsFd;
        let mut poll_fds = [PollFd::new(fan.as_fd(), PollFlags::POLLIN)];
        // Reusable string to avoid per-event heap allocations for proc paths.
        let mut proc_path = String::with_capacity(48);

        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }

            let events = match fan.read_events() {
                Ok(events) => events,
                Err(nix::errno::Errno::EAGAIN) => {
                    // Wait for readability instead of busy-sleeping.
                    let _ = poll(&mut poll_fds, PollTimeout::from(100u16));
                    continue;
                }
                Err(nix::errno::Errno::EINTR) => continue,
                Err(err) => {
                    warn!(?err, "fanotify read_events failed");
                    break;
                }
            };

            for event in &events {
                let Some(fd) = event.fd() else {
                    continue; // queue overflow
                };

                let pid = event.pid();
                if pid == self_pid || pid <= 0 {
                    continue;
                }

                let raw_fd = fd.as_raw_fd();

                // Resolve file path from fd (reuse buffer to avoid alloc).
                proc_path.clear();
                let _ = write!(proc_path, "/proc/self/fd/{raw_fd}");
                let file_path = match std::fs::read_link(&proc_path) {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                // Skip virtual/temp filesystems.
                let path_str = match file_path.to_str() {
                    Some(s) => s,
                    None => continue,
                };
                if SKIP_PREFIXES.iter().any(|prefix| path_str.starts_with(prefix)) {
                    continue;
                }

                // Only regular files with nonzero size.
                let meta = match std::fs::metadata(&file_path) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                if !meta.is_file() || meta.len() == 0 {
                    continue;
                }
                let file_meta = FileMeta {
                    size: meta.len(),
                    device: meta.st_dev(),
                    inode: meta.st_ino(),
                };

                // Resolve exe path of the opening process (reuse buffer).
                proc_path.clear();
                let _ = write!(proc_path, "/proc/{pid}/exe");
                let exe_path = match std::fs::read_link(&proc_path) {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                let file_path: Arc<Path> = Arc::from(file_path.as_path());
                let exe_path: Arc<Path> = Arc::from(exe_path.as_path());

                let mut buf = match buffer.lock() {
                    Ok(b) => b,
                    Err(poisoned) => poisoned.into_inner(),
                };
                buf.exes.entry(exe_path.clone()).or_insert(pid as u32);
                buf.maps.entry((exe_path, file_path)).or_insert(file_meta);
            }
        }

        trace!("fanotify reader loop exited");
    }

    pub fn drain(&self, time: u64) -> Vec<ObservationEvent> {
        let buf = {
            let mut guard = match self.buffer.lock() {
                Ok(b) => b,
                Err(poisoned) => poisoned.into_inner(),
            };
            std::mem::take(&mut *guard)
        };

        let mut events = Vec::with_capacity(buf.exes.len() + buf.maps.len());

        for (path, pid) in buf.exes {
            events.push(ObservationEvent::ExeSeen { path, pid });
        }

        for ((exe_path, file_path), fm) in buf.maps {
            let mut segment = MapSegment::from_arc(file_path, 0, fm.size, time);
            segment.device = fm.device;
            segment.inode = fm.inode;
            events.push(ObservationEvent::MapSeen {
                exe_path,
                map: segment,
            });
        }

        events
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn virtual_filesystems_are_not_marked() {
        assert!(is_virtual_filesystem("proc"));
        assert!(is_virtual_filesystem("tmpfs"));
        assert!(is_virtual_filesystem("fuse.portal"));
        assert!(!is_virtual_filesystem("btrfs"));
        assert!(!is_virtual_filesystem("ext4"));
        assert!(!is_virtual_filesystem("fuseblk"));
    }

    #[test]
    fn mountinfo_path_escapes_are_decoded() {
        assert_eq!(
            decode_mount_path(Path::new("/run/media/andy/My\\040Games")),
            Path::new("/run/media/andy/My Games")
        );
        assert_eq!(
            decode_mount_path(Path::new("/mnt/Steam\\134Library")),
            Path::new("/mnt/Steam\\Library")
        );
    }
}

impl std::fmt::Debug for FanotifyWatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (exes, maps) = self
            .buffer
            .lock()
            .map(|b| (b.exes.len(), b.maps.len()))
            .unwrap_or((0, 0));
        f.debug_struct("FanotifyWatcher")
            .field("buffered_exes", &exes)
            .field("buffered_maps", &maps)
            .field("active", &!self.stop.load(Ordering::Relaxed))
            .finish()
    }
}

impl Drop for FanotifyWatcher {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}
