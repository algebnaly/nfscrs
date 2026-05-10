use minibserde::{ByteArray, Decode, Encode};

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

pub const CREATE_SESSION4_FLAG_PERSIST: u32 = 0x0000_0001;
pub const CREATE_SESSION4_FLAG_CONN_BACK_CHAN: u32 = 0x0000_0002;
pub const CREATE_SESSION4_FLAG_CONN_RDMA: u32 = 0x0000_0004;

pub const SEQ4_STATUS_CB_PATH_DOWN: u32 = 0x00000001;
pub const SEQ4_STATUS_CB_GSS_CONTEXTS_EXPIRING: u32 = 0x00000002;
pub const SEQ4_STATUS_CB_GSS_CONTEXTS_EXPIRED: u32 = 0x00000004;
pub const SEQ4_STATUS_EXPIRED_ALL_STATE_REVOKED: u32 = 0x00000008;
pub const SEQ4_STATUS_EXPIRED_SOME_STATE_REVOKED: u32 = 0x00000010;
pub const SEQ4_STATUS_ADMIN_STATE_REVOKED: u32 = 0x00000020;
pub const SEQ4_STATUS_RECALLABLE_STATE_REVOKED: u32 = 0x00000040;
pub const SEQ4_STATUS_LEASE_MOVED: u32 = 0x00000080;
pub const SEQ4_STATUS_RESTART_RECLAIM_NEEDED: u32 = 0x00000100;
pub const SEQ4_STATUS_CB_PATH_DOWN_SESSION: u32 = 0x00000200;
pub const SEQ4_STATUS_BACKCHANNEL_FAULT: u32 = 0x00000400;
pub const SEQ4_STATUS_DEVID_CHANGED: u32 = 0x00000800;
pub const SEQ4_STATUS_DEVID_DELETED: u32 = 0x00001000;

pub type SecOId4 = Opaque;
pub type AttrNotice4 = NfsTime4;
pub type GssHandle4 = Opaque;
pub type SequenceId4 = u32;
pub type SlotId4 = u32;

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

pub type Count4 = u32;

pub const NFS4_SESSIONID_SIZE: usize = 16;
pub type SessionId4 = ByteArray<NFS4_SESSIONID_SIZE>; // opaque sessionid4[NFS4_SESSIONID_SIZE]

#[derive(Debug, Encode)]
#[repr(u32)]
pub enum CallbackSecParms4 {
    AUTH_NONE = crate::onc_rpc_defs::AUTH_NONE as u32, // AUTH_NONE
    AUTH_SYS = crate::onc_rpc_defs::AUTH_SYS as u32,
    RPCSEC_GSS = crate::onc_rpc_defs::RPCSEC_GSS as u32,
}
