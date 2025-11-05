use crate::{
    NFSCRSInnerError,
    nfs4_types::{Count4, NFSFH4, SeqId4},
    nfscrs_types::AbsolutePath,
    nfsv4_ops::{
        GetFH4ResultOk, Open4ResultOk, OpenDelegation4, OpenFlag4, Read4ResultOk, StableHow4,
        StateId4, Verifier4,
    },
    xdr_types::Opaque,
};

pub struct OpeningFile {
    pub file_handle: NFSFH4,
    pub state_id: StateId4,
    pub delegation: OpenDelegation4,
    pub share_access: u32,
    pub share_deny: u32,
    pub open_owner_seq_id: u32,
    pub open_flag: OpenFlag4,
    pub path: AbsolutePath<'static>,
}

pub struct OpeningFileBuilder {
    pub get_fh_result: GetFH4ResultOk,
    pub open_result: Open4ResultOk,
    pub share_access: u32,
    pub share_deny: u32,
    pub open_owner_seq_id: u32,
    pub open_flag: OpenFlag4,
    pub path: AbsolutePath<'static>,
}

impl OpeningFileBuilder {
    pub fn build(self) -> Result<OpeningFile, NFSCRSInnerError> {
        Ok(OpeningFile {
            state_id: self.open_result.state_id,
            file_handle: self.get_fh_result.object,
            delegation: self.open_result.delegation,
            share_access: self.share_access,
            share_deny: self.share_deny,
            open_owner_seq_id: self.open_owner_seq_id,
            open_flag: self.open_flag,
            path: self.path,
        })
    }
}

pub struct OpenedFile {
    pub file_handle: NFSFH4,
    pub state_id: StateId4,
    pub delegation: OpenDelegation4,
    pub share_access: u32,
    pub share_deny: u32,
    pub offset: usize,
    pub open_owner_seq_id: SeqId4,
    pub path: AbsolutePath<'static>,
}

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
