use std::{
    fmt::Formatter,
    hash::{DefaultHasher, Hash, Hasher},
    iter,
    sync::{Mutex, MutexGuard},
};

use dashmap::DashMap;
use minibserde::ByteBuf;

use crate::{
    FileKey, OpenFileState,
    nfscrs_error::NFSCRSInnerError,
    nfscrs_types::{AbsolutePath, AbsolutePathOwned},
};

pub const PATH_LOCKS_NUM: usize = 1024;

pub struct OpenOwner {
    pub owner: ByteBuf,
    seq_id: Mutex<u32>,

    pub files: DashMap<FileKey, OpenFileState>,
    pub path_map: DashMap<AbsolutePathOwned, FileKey>,
    path_locks: Vec<Mutex<()>>, // protect `files` and `path_map` keep in sync
}

impl std::fmt::Debug for OpenOwner {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let owner_str = String::from_utf8_lossy(&self.owner);
        f.debug_struct("OpenOwner")
            .field("owner", &owner_str)
            .field(
                "seq_id",
                &self
                    .seq_id
                    .try_lock()
                    .map_or("\"seq_id locked\"".to_string(), |v| v.to_string()),
            )
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
            seq_id: Mutex::new(0),
            files: DashMap::new(),
            path_map: DashMap::new(),
            path_locks,
        }
    }

    pub fn lock_path<'a>(
        &'a self,
        path: &AbsolutePath,
    ) -> Result<MutexGuard<'a, ()>, NFSCRSInnerError> {
        let mut hasher = DefaultHasher::new();
        path.hash(&mut hasher);
        let pos = hasher.finish() as usize % PATH_LOCKS_NUM;
        self.path_locks[pos]
            .lock()
            .map_err(|e| NFSCRSInnerError::PoisonedMutex(format!("{:?}", e)))
    }

    // lock both seq_id and one path, to avoid manual lock those two.
    pub(crate) fn lock_seq_id_and_path<'a>(
        &'a self,
        path: &AbsolutePath,
    ) -> Result<OpenOwnerGuard<'a>, NFSCRSInnerError> {
        let seq_id_guard = self
            .seq_id
            .lock()
            .map_err(|e| NFSCRSInnerError::PoisonedMutex(format!("{:?}", e)))?;
        let path_guard = self
            .lock_path(path)
            .map_err(|e| NFSCRSInnerError::PoisonedMutex(format!("{:?}", e)))?;
        Ok(OpenOwnerGuard {
            seq_id_guard,
            path_guard,
        })
    }
}

pub(crate) struct OpenOwnerGuard<'a> {
    pub(crate) seq_id_guard: MutexGuard<'a, u32>,
    pub(crate) path_guard: MutexGuard<'a, ()>,
}
