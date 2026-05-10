use minibserde::{Decode, Encode};

use crate::{
    client::ClientOwner4,
    nfs4_1_types::{
        CallbackSecParms4, Count4, GssHandle4, NfsImplId4, SecOId4, SequenceId4, ServerOwner4,
        SessionId4,
    },
    nfs4_types::{BitMap4, ClientId4},
    onc_rpc_defs,
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
    pub eia_clientowner: ClientOwner4,
    pub eia_flags: u32,
    pub eia_state_protect: StateProtect4A,
    pub eia_client_impl_id: Vec<NfsImplId4>, // at most of length 1
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
    pub eir_client_id: ClientId4,
    pub eir_sequence_id: SequenceId4,
    pub eir_flags: u32,
    pub eir_state_protect: StateProtect4R,
    pub eir_server_owner: ServerOwner4,
    pub eir_server_scope: Opaque, // With Max Length of NFS4_OPAQUE_LIMIT
    pub eir_server_impl_id: Vec<NfsImplId4>, // with max length of 1
}

#[derive(Debug, Decode)]
#[repr(u32)]
pub enum ExchangeID4Result {
    NFS4_OK(ExchangeID4ResultOk),
    #[minibserde(catch_all)]
    Default(u32),
}

#[derive(Debug, Encode, Decode)]
pub struct ChannelAttrs4 {
    pub ca_headerpadsize: Count4,
    pub ca_maxrequestsize: Count4,
    pub ca_maxresponsesize: Count4,
    pub ca_maxresponsesize_cached: Count4,
    pub ca_maxoperations: Count4,
    pub ca_maxrequests: Count4,
    pub ca_rdma_ird: Vec<u32>, // at most of length 1
}

impl Default for ChannelAttrs4 {
    fn default() -> Self {
        Self {
            ca_headerpadsize: 4096,
            ca_maxrequestsize: 64 * 1024 * 1024,
            ca_maxresponsesize: 64 * 1024 * 1024,
            ca_maxoperations: 1024,
            ca_maxrequests: 1024,
            ca_rdma_ird: Vec::new(),
            ca_maxresponsesize_cached: 4096,
        }
    }
}

#[derive(Debug, Encode)]
pub struct CreateSession4Args {
    pub csa_client_id: ClientId4,
    pub csa_sequence: SequenceId4,
    pub csa_flags: u32,
    pub csa_fore_chan_attrs: ChannelAttrs4,
    pub csa_back_chan_attrs: ChannelAttrs4,
    pub csa_cb_program: u32,
    pub csa_sec_parms: Vec<CallbackSecParms4>,
}

impl CreateSession4Args {
    pub fn new(client_id: ClientId4, sequence: u32) -> Self {
        Self {
            csa_client_id: client_id,
            csa_sequence: sequence,
            csa_flags: 0,
            csa_fore_chan_attrs: ChannelAttrs4::default(),
            csa_back_chan_attrs: ChannelAttrs4::default(),
            csa_sec_parms: vec![CallbackSecParms4::AUTH_NONE],
            csa_cb_program: 0,
        }
    }
}

#[derive(Debug, Decode)]
pub struct CreateSession4ResultOk {
    pub csr_sessionid: SessionId4,
    pub csr_sequence: SequenceId4,
    pub csr_flags: u32,
    pub csr_fore_chan_attrs: ChannelAttrs4,
    pub csr_back_chan_attrs: ChannelAttrs4,
}

#[derive(Debug, Decode)]
#[repr(u32)]
pub enum CreateSession4Result {
    NFS4_OK(CreateSession4ResultOk),
    #[minibserde(catch_all)]
    Default(u32),
}
