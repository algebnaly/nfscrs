use std::{
    fmt::Formatter, hash::{DefaultHasher, Hash, Hasher}, iter, sync::{LockResult, Mutex, MutexGuard, atomic::{AtomicU32, Ordering}}
};

use dashmap::DashMap;
use serde_bytes::ByteBuf;

use crate::{
    FileKey, OpenFileState,
    nfscrs_types::{AbsolutePath, AbsolutePathOwned},
};

pub const PATH_LOCKS_NUM: usize = 1024;

pub struct OpenOwner {
    pub owner: ByteBuf,
    pub seq_id: AtomicU32,

    pub files: DashMap<FileKey, OpenFileState>,
    pub path_map: DashMap<AbsolutePathOwned, FileKey>,
    pub path_locks: Vec<Mutex<()>>, // protect `files` and `path_map` keep in sync
}

impl std::fmt::Debug for OpenOwner {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let owner_str = String::from_utf8_lossy(&self.owner);
        f.debug_struct("OpenOwner")
            .field("owner", &owner_str)
            .field("seq_id", &self.seq_id.load(Ordering::Relaxed))
            .field("files_count", &self.files.len())
            .field("path_map_count", &self.path_map.len())
            .finish()
    }
}

impl OpenOwner {
    pub fn new(owner: ByteBuf) -> Self {
        let path_locks: Vec<Mutex<()>> = iter::repeat_with(|| Mutex::new(()))
            .take(PATH_LOCKS_NUM)
            .collect();

        Self {
            owner,
            seq_id: AtomicU32::new(0),
            files: DashMap::new(),
            path_map: DashMap::new(),
            path_locks,
        }
    }

    pub fn lock_path<'a>(&'a self, path: &AbsolutePath) -> LockResult<MutexGuard<'a ,()>> {
        let mut hasher = DefaultHasher::new();
        path.hash(&mut hasher);
        let pos = hasher.finish() as usize % PATH_LOCKS_NUM;
        self.path_locks[pos].lock()
    }
}
