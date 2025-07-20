use crate::{
    NFSCRSInnerError,
    nfs4types::NFSFH4,
    nfscrs_types::AbsolutePath,
    nfsv4ops::{GetFH4ResultOk, Open4ResultOk, OpenDelegation4, Read4ResultOk, StateId4},
    xdr_types::Opaque,
};

pub struct OpeningFile {
    pub file_handle: NFSFH4,
    pub state_id: StateId4,
    pub delegation: OpenDelegation4,
    pub share_access: u32,
    pub share_deny: u32,
    pub open_owner_seq_id: u32,
    pub path: AbsolutePath<'static>,
}

pub struct OpeningFileBuilder {
    pub get_fh_result: GetFH4ResultOk,
    pub open_result: Open4ResultOk,
    pub share_access: u32,
    pub share_deny: u32,
    pub open_owner_seq_id: u32,
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
    pub path: AbsolutePath<'static>,
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
