use crate::fattr4_utils::const_attr_mask;

pub const READDIR_MAX_COUNT: u32 = 1024; // 4k bytes per request
pub const READDIR_DEFAULT_ATTR: &[u32] =
    &const_attr_mask::<1>(&[crate::fattr4::fattr4_names::FATTR4_TYPE]);
pub const SLOT_NUM: u32 = 64;
