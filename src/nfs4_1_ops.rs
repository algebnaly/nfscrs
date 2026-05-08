use minibserde::{Decode, Encode};

use crate::{
    client::ClientOwner4,
    nfs4_1_types::{GssHandle4, NfsImplId4, SecOId4, SequenceId4, ServerOwner4},
    nfs4_types::{BitMap4, ClientId4},
    xdr_types::Opaque,
};

#[derive(Debug, Encode, Decode)]
pub struct StateProtectOps4 {
    pub spo_must_enforce: BitMap4,
    pub spo_must_allow: BitMap4,
}

#[derive(Debug, Encode)]
pub struct SsvSpParms4 {
    pub spo_ops: StateProtectOps4,
    pub ssp_hash_algs: Vec<SecOId4>,
    pub ssp_encr_algs: Vec<SecOId4>,
    pub ssp_window: u32,
    pub ssp_num_gss_handles: u32,
}

#[derive(Debug, Encode)]
#[repr(u32)]
pub enum StateProtect4A {
    SP4_NONE = 0,
    SP4_MACH_CRED(StateProtectOps4) = 1,
    SP4_SSV(SsvSpParms4) = 2,
}

#[derive(Debug, Encode)]
pub struct Exchange4Args {
    eia_clientowner: ClientOwner4,
    eia_flags: u32,
    eia_state_protect: StateProtect4A,
    eia_client_impl_id: Vec<NfsImplId4>, // at most of length 1
}

#[derive(Debug, Decode)]
pub struct SsvProtInfo4 {
    pub spi_ops: StateProtectOps4,
    pub spi_hash_alg: u32,
    pub spi_encr_alg: u32,
    pub spi_ssv_len: u32,
    pub spi_window: u32,
    pub spi_handles: Vec<GssHandle4>,
}

#[derive(Debug, Decode)]
#[repr(u32)]
pub enum StateProtect4R {
    SP4_NONE = 0,
    SP4_MACH_CRED(StateProtectOps4) = 1,
    SP4_SSV(SsvProtInfo4) = 2,
}

#[derive(Debug, Decode)]
pub struct ExchangeID4ResultOk {
    pub eir_clientid: ClientId4,
    pub eir_sequenceid: SequenceId4,
    pub eir_flags: u32,
    pub eir_state_protect: StateProtect4R,
    pub eir_server_owner: ServerOwner4,
    pub eir_server_scope: Opaque, // With Max Length of NFS4_OPAQUE_LIMIT
    pub eir_server_impl_id: NfsImplId4, // with max length of 1
}

#[derive(Debug, Decode)]
#[repr(u32)]
pub enum ExchangeID4Result {
    NFS4_OK(ExchangeID4ResultOk),
    #[minibserde(catch_all)]
    Default(u32),
}
