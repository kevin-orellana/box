use super::*;

fn event(kind: u32, source: &str) -> RawEvent {
    // Every field accepts zero as a representation. Decoding validates its meaning.
    let mut event: RawEvent = unsafe { std::mem::zeroed() };
    event.kind = kind;
    event.phase = AUTH;
    event.valid = 1;
    event.source_identity = FILE_IDENTITY;
    event.path[..source.len()].copy_from_slice(source.as_bytes());
    event
}

#[test]
fn bridge_layout_matches_rust() {
    assert_eq!(std::mem::size_of::<RawEvent>(), unsafe {
        box_es_event_size()
    });
}

#[test]
fn open_flags_use_kernel_access_bits_and_preserve_append() {
    let mut raw = event(OPEN, "/file");
    raw.flags = FREAD | FWRITE | libc::O_APPEND as u32;
    let plan = Plan::decode(&raw).unwrap();
    assert_eq!(plan.checks.len(), 2);
    assert_eq!(plan.checks[0].operation, FsOperation::ReadContent);
    assert_eq!(plan.checks[1].operation, FsOperation::WriteContent);
    raw.flags = FREAD | libc::O_TRUNC as u32;
    assert_eq!(Plan::decode(&raw).unwrap().checks.len(), 2);
    raw.flags = 0;
    assert!(Plan::decode(&raw).is_err());
}

#[test]
fn create_and_unlink_preserve_object_types() {
    for (mode, create, remove) in [
        (
            libc::S_IFREG,
            FsOperation::WriteContent,
            FsOperation::RemoveFile,
        ),
        (
            libc::S_IFDIR,
            FsOperation::CreateDir,
            FsOperation::RemoveDir,
        ),
        (libc::S_IFLNK, FsOperation::Symlink, FsOperation::RemoveFile),
    ] {
        let mut raw = event(CREATE, "/new");
        raw.source_identity = PARENT_IDENTITY;
        raw.mode = mode as u32 | 0o600;
        assert_eq!(Plan::decode(&raw).unwrap().checks[0].operation, create);
        raw.kind = UNLINK;
        raw.source_identity = FILE_IDENTITY;
        assert_eq!(Plan::decode(&raw).unwrap().checks[0].operation, remove);
    }
    let mut raw = event(CREATE, "/device");
    raw.source_identity = PARENT_IDENTITY;
    raw.mode = libc::S_IFCHR as u32;
    assert!(Plan::decode(&raw).is_err());
}

#[test]
fn rename_checks_read_and_both_move_targets_and_authorizes_replacement() {
    let mut raw = event(RENAME, "/source");
    raw.destination[..12].copy_from_slice(b"/destination");
    raw.destination_identity = PARENT_IDENTITY;
    let plan = Plan::decode(&raw).unwrap();
    assert_eq!(plan.checks.len(), 3);
    assert_eq!(plan.checks[0].operation, FsOperation::ReadContent);
    assert_eq!(plan.checks[1].path, Path::new("/source"));
    assert_eq!(plan.checks[2].path, Path::new("/destination"));
    raw.destination_exists = 1;
    // An existing destination must carry its own kernel identity.
    assert!(Plan::decode(&raw).is_err());
    raw.destination_identity = FILE_IDENTITY;
    raw.destination_mode = libc::S_IFREG as u32;
    let plan = Plan::decode(&raw).unwrap();
    assert_eq!(plan.checks.len(), 5);
    assert_eq!(plan.checks[3].operation, FsOperation::RemoveFile);
    assert_eq!(plan.checks[4].operation, FsOperation::WriteContent);
    assert_eq!(plan.identities[1].path, Path::new("/destination"));
    raw.destination_mode = libc::S_IFDIR as u32;
    assert!(Plan::decode(&raw).is_err());
}

#[test]
fn event_only_open_checks_content_and_unknown_flags_stay_refused() {
    let mut raw = event(OPEN, "/file");
    raw.flags = (libc::O_EVTONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u32;
    let plan = Plan::decode(&raw).unwrap();
    assert_eq!(plan.checks.len(), 1);
    assert_eq!(plan.checks[0].operation, FsOperation::ReadContent);
    for flags in [
        0,
        libc::O_EVTONLY as u32 | 0x80000000,
        libc::O_EVTONLY as u32 | libc::O_TRUNC as u32,
    ] {
        raw.flags = flags;
        assert!(Plan::decode(&raw).is_err(), "{flags:#x}");
    }
}

#[test]
fn execute_only_open_uses_the_existing_exec_operation() {
    let mut raw = event(OPEN, "/program");
    raw.flags = (libc::O_EXEC | libc::O_CLOEXEC | libc::O_NOCTTY | libc::O_NONBLOCK) as u32;
    assert_eq!(raw.flags, 0x41020004);
    let plan = Plan::decode(&raw).unwrap();
    assert_eq!(plan.checks.len(), 1);
    assert_eq!(plan.checks[0].operation, FsOperation::ExecFile);
    raw.flags |= libc::O_EVTONLY as u32;
    assert!(Plan::decode(&raw).is_err());
}

#[test]
fn replacement_rechecks_the_kernel_destination_identity() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source");
    let destination = directory.path().join("destination");
    std::fs::write(&source, "source").unwrap();
    std::fs::write(&destination, "old").unwrap();
    let mut raw = event(RENAME, source.to_str().unwrap());
    let name = destination.to_str().unwrap().as_bytes();
    raw.destination[..name.len()].copy_from_slice(name);
    raw.source_dev = source.metadata().unwrap().dev();
    raw.source_ino = source.metadata().unwrap().ino();
    raw.destination_exists = 1;
    raw.destination_identity = FILE_IDENTITY;
    raw.destination_mode = libc::S_IFREG as u32;
    raw.destination_dev = destination.metadata().unwrap().dev();
    raw.destination_ino = destination.metadata().unwrap().ino();
    let plan = Plan::decode(&raw).unwrap();
    plan.verify().unwrap();
    std::fs::rename(&destination, directory.path().join("old")).unwrap();
    std::fs::write(&destination, "replacement").unwrap();
    assert!(plan.verify().is_err());
}

#[test]
fn malformed_paths_and_notifications_cannot_authorize() {
    let mut raw = event(TRUNCATE, "/file");
    raw.phase = NOTIFY;
    assert!(Plan::decode(&raw).is_err());
    raw.phase = AUTH;
    raw.valid = 0;
    assert!(Plan::decode(&raw).is_err());
    raw.valid = 1;
    raw.path.fill(b'a');
    assert!(Plan::decode(&raw).is_err());
    raw.path.fill(0);
    raw.path[..5].copy_from_slice(b"/x/\xffy");
    assert!(Plan::decode(&raw).is_err());
}

#[test]
fn replaced_file_identity_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("file");
    std::fs::write(&path, "original").unwrap();
    let metadata = path.metadata().unwrap();
    let plan = Plan {
        checks: vec![],
        identities: vec![Identity {
            path: path.clone(),
            device: metadata.dev(),
            inode: metadata.ino(),
        }],
    };
    plan.verify().unwrap();
    std::fs::rename(&path, directory.path().join("original")).unwrap();
    std::fs::write(&path, "replacement").unwrap();
    assert!(plan.verify().is_err());
}

#[test]
fn sequence_gaps_and_duplicates_fail() {
    let mut tracker = Tracker::default();
    assert!(tracker.sequence(0));
    assert!(tracker.sequence(1));
    assert!(!tracker.sequence(3));
    assert!(!tracker.sequence(3));
}
