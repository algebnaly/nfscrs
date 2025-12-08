use std::sync::{
    RwLock,
    atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
};

use crate::{
    NFSCRSInnerError,
    nfs4_types::{Count4, FSId4, NFSFH4},
    nfscrs_types::{AbsolutePath, AbsolutePathOwned},
    nfsv4_ops::{
        GetFH4ResultOk, Open4ResultOk, Read4ResultOk, StableHow4, StateId4,
        Verifier4, open_params,
    },
    xdr_types::Opaque,
};

#[derive(Debug)]
pub struct OpenedFileBuilder {
    pub get_fh_result: GetFH4ResultOk,
    pub open_result: Open4ResultOk,
    pub requested_share_access: u32,
    pub requested_share_deny: u32,
    pub path: AbsolutePath<'static>,
    pub file_key: FileKey,
}

impl OpenedFileBuilder {
    pub fn build(self) -> Result<OpenedFile, NFSCRSInnerError> {
        Ok(OpenedFile {
            file_key: self.file_key,
            file_handle: self.get_fh_result.object,
            requested_share_access: self.requested_share_access,
            requested_share_deny: self.requested_share_deny,
            path: self.path,
            offset: 0,
        })
    }
}

#[derive(Debug)]
pub struct OpenedFile {
    pub file_handle: NFSFH4,
    pub file_key: FileKey,
    pub requested_share_access: u32,
    pub requested_share_deny: u32,
    pub offset: usize,
    pub path: AbsolutePathOwned,
}

impl OpenedFile {}

#[derive(Debug, Clone)]
pub struct OpenOptions {
    pub read: bool,
    pub write: bool,
    pub create: bool,
    pub truncate: bool,
}

impl OpenOptions {
    pub fn new() -> Self {
        Self {
            read: true,
            write: false,
            create: false,
            truncate: false,
        }
    }

    pub fn read(mut self, read: bool) -> Self {
        self.read = read;
        self
    }

    pub fn write(mut self, write: bool) -> Self {
        self.write = write;
        self
    }

    pub fn create(mut self, create: bool) -> Self {
        self.create = create;
        self
    }
    pub fn truncate(mut self, truncate: bool) -> Self {
        self.truncate = truncate;
        self
    }
    
    pub fn get_share_access(&self) -> u32 {
        let share_access = if self.read && !self.write {
            open_params::OPEN4_SHARE_ACCESS_READ
        } else if !self.read && self.write {
            open_params::OPEN4_SHARE_ACCESS_WRITE
        } else {
            open_params::OPEN4_SHARE_ACCESS_BOTH
        };
        share_access
    }
}

impl Default for OpenOptions {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ReadResult {
    pub eof: bool,
    pub data: Opaque,
}

impl From<Read4ResultOk> for ReadResult {
    fn from(value: Read4ResultOk) -> Self {
        Self {
            eof: value.eof,
            data: value.data,
        }
    }
}

pub struct WriteResult {
    pub count: Count4,
    pub committed: StableHow4,
    pub writeverf: Verifier4,
}

pub struct OpenFileState {
    refcount: AtomicUsize,
    file_handle: NFSFH4,
    file_key: FileKey,
    state_id: RwLock<StateId4>,
    pub share_access: AtomicU32,
    pub share_deny: AtomicU32,
    pub confirmed: AtomicBool,
    rflags: AtomicU32,
    // we do not support file lock for now
    //pub delegation: RwLock<Option<OpenDelegation4>>,
}

impl OpenFileState {
    pub fn new(
        file_handle: NFSFH4,
        file_key: FileKey,
        state_id: StateId4,
        share_access: u32,
        share_deny: u32,
        rflags: u32
    ) -> Self {
        let confirmed = rflags & crate::nfs4_open::OPEN4_RESULT_CONFIRM == 0;
        Self {
            refcount: AtomicUsize::new(1),
            file_handle,
            file_key,
            state_id: RwLock::new(state_id),
            share_access: AtomicU32::new(share_access),
            share_deny: AtomicU32::new(share_deny),
            confirmed: AtomicBool::new(confirmed),
            rflags: AtomicU32::new(rflags),
        }
    }

    pub fn get_state_id(&self) -> Result<StateId4, NFSCRSInnerError> {
        let state_id_guard = self.state_id.read().map_err(|e| {
            NFSCRSInnerError::PoisonedMutex(format!("failed to read state_id: {:?}", e))
        })?;

        return Ok((&*state_id_guard).clone());
    }

    pub fn update_state_id(&mut self, state_id: StateId4) -> Result<(), NFSCRSInnerError> {
        let mut state_id_guard = self.state_id.write().map_err(|e| {
            NFSCRSInnerError::PoisonedMutex(format!("failed to write state_id: {:?}", e))
        })?;
        *state_id_guard = state_id;
        Ok(())
    }

    pub fn get_ref_count(&self) -> usize {
        self.refcount.load(Ordering::Acquire)
    }

    pub fn ref_count_dec(&self) -> usize {
        self.refcount.fetch_sub(1, Ordering::SeqCst)
    }
    pub fn ref_count_inc(&self) -> usize {
        self.refcount.fetch_add(1, Ordering::SeqCst)
    }

    pub fn need_confirm(&self) -> bool {
        !self.confirmed.load(Ordering::Acquire)
    }

    pub fn get_opened_file(
        &self,
        requested_share_access: u32,
        requested_share_deny: u32,
        path: AbsolutePathOwned,
    ) -> OpenedFile {
        OpenedFile {
            file_handle: self.file_handle.clone(),
            file_key: self.file_key,
            requested_share_access,
            requested_share_deny,
            offset: 0,
            path,
        }
    }
    pub(crate) fn set_confirmed(&mut self) {
        self.confirmed.store(true, Ordering::Release);
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct FileKey {
    pub fsid: FSId4,
    pub file_id: u64,
}
