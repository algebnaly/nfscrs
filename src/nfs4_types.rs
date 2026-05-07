use minibserde::{Decode, Encode};

use crate::xdr_types::Opaque;

pub type AttrList4 = Opaque;
pub type BitMap4 = Vec<u32>;
pub type ChangeId4 = u64;
pub type ClientId4 = u64;
pub type Count4 = u32;
pub type Length4 = u64;
pub type Mode4 = u32;
pub type NFSCookie4 = u64;
pub type NFSFH4 = minibserde::ByteBuf; // with max size NFS4_FHSIZE
pub type NFSLease4 = u32;
pub type Offset4 = u64;
pub type QOP4 = u32;

pub type sec_oid4 = Opaque;
pub type SeqId4 = u32;
pub type Utf8String = Opaque;
pub type Utf8StrCis = Utf8String;
pub type Utf8StrCs = Utf8String;
pub type Utf8StrMixed = Utf8String;
pub type Component4 = Utf8String;
pub type LinkText4 = Opaque;
pub type AsciiRequired4 = Utf8String;
pub type NfsLockId4 = u64;
pub type PathName4 = Vec<Component4>;

#[derive(Debug, Encode, Decode)]
pub struct SpecData4 {
    pub spec_data_1: u32, /* major device number */
    pub spec_data_2: u32, /* minor device number */
}

#[derive(Debug, Encode, Decode, PartialEq, Eq, Hash, Clone, Copy)]
pub struct FSId4 {
    pub major: u64,
    pub minor: u64,
}

#[derive(Debug, Encode, Decode)]
pub struct NFSTime4 {
    pub seconds: i64,
    pub nseconds: u32,
}

pub mod time_how4 {
    pub const SET_TO_SERVER_TIME4: u32 = 0;
    pub const SET_TO_CLIENT_TIME4: u32 = 1;
}

#[derive(Debug, Encode, Decode)]
#[repr(u32)]
pub enum SetTime4 {
    SET_TO_CLIENT_TIME4(NFSTime4) = time_how4::SET_TO_CLIENT_TIME4,
    #[minibserde(catch_all)]
    Default(u32),
}

#[derive(Debug, Encode, Decode)]
#[repr(u32)]
pub enum NFSFType4 {
    NF4REG = 1,       /* Regular File */
    NF4DIR = 2,       /* Directory */
    NF4BLK = 3,       /* Special File - block device */
    NF4CHR = 4,       /* Special File - character device */
    NF4LNK = 5,       /* Symbolic Link */
    NF4SOCK = 6,      /* Special File - socket */
    NF4FIFO = 7,      /* Special File - fifo */
    NF4ATTRDIR = 8,   /* Attribute Directory */
    NF4NAMEDATTR = 9, /* Named Attribute */
}

#[derive(Debug, Encode, Decode)]
pub struct FSLocation4 {
    pub server: Utf8StrCis,
    pub rootpath: PathName4,
}

#[derive(Debug, Encode, Decode)]
pub struct FSLocations4 {
    pub fs_root: PathName4,
    pub fs_locations: Vec<FSLocation4>,
}

pub type AceType4 = u32;
pub type AceFlag4 = u32;
pub type AceMask4 = u32;

#[derive(Debug, Encode, Decode)]
pub struct NFSAce4 {
    pub type_field: AceType4,
    pub flag: AceFlag4,
    pub access_mask: AceMask4,
    pub who: Utf8StrMixed,
}

pub const NFS4_FHSIZE: usize = 128;
pub const NFS4_VERIFIER_SIZE: usize = 8;
pub const NFS4_OTHER_SIZE: usize = 12;
pub const NFS4_OPAQUE_LIMIT: usize = 1024;

pub const NFS4_INT64_MAX: i64 = i64::MAX;
pub const NFS4_UINT64_MAX: u64 = u64::MAX;
pub const NFS4_INT32_MAX: i32 = i32::MAX;
pub const NFS4_UINT32_MAX: u32 = u32::MAX;
