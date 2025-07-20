use crate::xdr_types::Opaque;

pub type AttrList4 = Opaque;
pub type BitMap4 = Vec<u32>;
pub type ChangeId4 = u64;
pub type ClientId4 = u64;
pub type Count4 = u32;
pub type Length4 = u64;
pub type Mode4 = u32;
pub type NFSCookie4 = u64;
pub type NFSFH4 = serde_bytes::ByteBuf; // with max size NFS4_FHSIZE
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



pub type AceType4 = u32;
pub type AceFlag4 = u32;
pub type AceMask4 = u32;



pub const NFS4_FHSIZE: usize = 128;
pub const NFS4_VERIFIER_SIZE: usize = 8;
pub const NFS4_OTHER_SIZE: usize = 12;
pub const NFS4_OPAQUE_LIMIT: usize = 1024;

pub const NFS4_INT64_MAX: usize = 0x7fffffffffffffff;
pub const NFS4_UINT64_MAX: usize = 0xffffffffffffffff;
pub const NFS4_INT32_MAX: usize = 0x7fffffff;
pub const NFS4_UINT32_MAX: usize = 0xffffffff;
