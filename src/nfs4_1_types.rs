use minibserde::{Decode, Encode};

use crate::{
    nfs4_types::{Utf8StrCis, Utf8StrCs},
    xdr_types::Opaque,
};

pub const EXCHGID4_FLAG_SUPP_MOVED_REFER: u32 = 0x0000_0001;
pub const EXCHGID4_FLAG_SUPP_MOVED_MIGR: u32 = 0x0000_0002;

pub const EXCHGID4_FLAG_BIND_PRINC_STATEID: u32 = 0x0000_0100;

pub const EXCHGID4_FLAG_USE_NON_PNFS: u32 = 0x0001_0000;
pub const EXCHGID4_FLAG_USE_PNFS_MDS: u32 = 0x0002_0000;
pub const EXCHGID4_FLAG_USE_PNFS_DS: u32 = 0x0004_0000;

pub const EXCHGID4_FLAG_MASK_PNFS: u32 = 0x0007_0000;

pub const EXCHGID4_FLAG_UPD_CONFIRMED_REC_A: u32 = 0x4000_0000;
pub const EXCHGID4_FLAG_CONFIRMED_R: u32 = 0x8000_0000;

pub type SecOId4 = Opaque;
pub type AttrNotice4 = NfsTime4;
pub type GssHandle4 = Opaque;
pub type SequenceId4 = u32;

#[derive(Debug, Encode, Decode)]
pub struct NfsTime4 {
    pub seconds: i64,
    pub nseconds: u32,
}

#[derive(Debug, Encode, Decode)]
pub struct NfsImplId4 {
    pub nii_domain: Utf8StrCis,
    pub nii_name: Utf8StrCs,
    pub nii_date: NfsTime4,
}

#[derive(Debug, Encode, Decode)]
pub struct ServerOwner4 {
    pub so_minor_id: u64,
    pub so_major_id: Opaque, // With Max Length of NFS4_OPAQUE_LIMIT
}
