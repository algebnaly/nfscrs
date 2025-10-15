use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use xdr_brk::from_bytes;

use crate::{
    NFSCRSInnerError,
    fattr4_utils::{attr_mask_to_list, fattr4_from_mode},
    nfs4_types::{
        AsciiRequired4, AttrList4, BitMap4, ChangeId4, FSId4, FSLocations4, Mode4, NFSAce4, NFSFH4,
        NFSFType4, NFSLease4, NFSTime4, SetTime4, SpecData4, Utf8StrMixed,
    },
    nfsv4_ops::NFSStat4,
};

use xdr_brk::deserialize_len;

// here, we use `X-Macro` pattern to reduce repetition
macro_rules! for_each_fattr4 {
    ($macro:ident) => {
        $macro!(
        (FATTR4_SUPPORTED_ATTRS, BitMap4, 0),
        (FATTR4_TYPE, NFSFType4, 1),
        (FATTR4_FH_EXPIRE_TYPE, u32, 2),
        (FATTR4_CHANGE, ChangeId4, 3),
        (FATTR4_SIZE, u64, 4),
        (FATTR4_LINK_SUPPORT, bool, 5),
        (FATTR4_SYMLINK_SUPPORT, bool, 6),
        (FATTR4_NAMED_ATTR, bool, 7),
        (FATTR4_FSID, FSId4, 8),
        (FATTR4_UNIQUE_HANDLES, bool, 9),
        (FATTR4_LEASE_TIME, NFSLease4, 10),
        (FATTR4_RDATTR_ERROR, NFSStat4, 11),
        (FATTR4_FILEHANDLE, NFSFH4, 19) ,// this is not a typo, it does a mandatory attribute
        (FATTR4_ACL, Vec<NFSAce4>, 12),
        (FATTR4_ACLSUPPORT, u32, 13),
        (FATTR4_ARCHIVE, bool, 14),
        (FATTR4_CANSETTIME, bool, 15),
        (FATTR4_CASE_INSENSITIVE, bool, 16),
        (FATTR4_CASE_PRESERVING, bool, 17),
        (FATTR4_CHOWN_RESTRICTED, bool, 18),
        (FATTR4_FILEID, u64, 20),
        (FATTR4_FILES_AVAIL, u64, 21),
        (FATTR4_FILES_FREE, u64, 22),
        (FATTR4_FILES_TOTAL, u64, 23),
        (FATTR4_FS_LOCATIONS, FSLocations4, 24),
        (FATTR4_HIDDEN, bool, 25),
        (FATTR4_HOMOGENEOUS, bool, 26),
        (FATTR4_MAXFILESIZE, u64, 27),
        (FATTR4_MAXLINK, u32, 28),
        (FATTR4_MAXNAME, u32, 29),
        (FATTR4_MAXREAD, u64, 30),
        (FATTR4_MAXWRITE, u64, 31),
        (FATTR4_MIMETYPE, AsciiRequired4, 32),
        (FATTR4_MODE, Mode4, 33),
        (FATTR4_NO_TRUNC, bool, 34),
        (FATTR4_NUMLINKS, u32, 35),
        (FATTR4_OWNER, Utf8StrMixed, 36),
        (FATTR4_OWNER_GROUP, Utf8StrMixed, 37),
        (FATTR4_QUOTA_AVAIL_HARD, u64, 38),
        (FATTR4_QUOTA_AVAIL_SOFT, u64, 39),
        (FATTR4_QUOTA_USED, u64, 40),
        (FATTR4_RAWDEV, SpecData4, 41),
        (FATTR4_SPACE_AVAIL, u64, 42),
        (FATTR4_SPACE_FREE, u64, 43),
        (FATTR4_SPACE_TOTAL, u64, 44),
        (FATTR4_SPACE_USED, u64, 45),
        (FATTR4_SYSTEM, bool, 46),
        (FATTR4_TIME_ACCESS, NFSTime4, 47),
        (FATTR4_TIME_ACCESS_SET, SetTime4, 48),
        (FATTR4_TIME_BACKUP, NFSTime4, 49),
        (FATTR4_TIME_CREATE, NFSTime4, 50),
        (FATTR4_TIME_DELTA, NFSTime4, 51),
        (FATTR4_TIME_METADATA, NFSTime4, 52),
        (FATTR4_TIME_MODIFY, NFSTime4, 53),
        (FATTR4_TIME_MODIFY_SET, SetTime4, 54),
        (FATTR4_MOUNTED_ON_FILEID, u64, 55),
        );
    };
}

macro_rules! define_fattr4_enum {
    ($( ( $variant:ident, $type:ty, $discriminant:expr ) ),* $(,)?) => {
        #[derive(Debug)]
        #[repr(u32)]
        pub enum FAttr4Type {
            $(
                $variant($type) = $discriminant,
            )*
        }
        impl FAttr4Type {
            pub fn from_bitnum(data: &[u8], index: usize) -> Result<Self, NFSCRSInnerError> {
                match index {
                    $(
                        $discriminant => {
                            let value: $type = from_bytes(data)?;
                            Ok(FAttr4Type::$variant(value))
                        }
                    )*
                    _ => Err(NFSCRSInnerError::InvalidArgument(format!("Invalid index: {}", index))),
                }
            }
        }
    };
}

macro_rules! define_fattr4_iterator {
    ($( ( $variant:ident, $type:ty, $discriminant:expr ) ),* $(,)?) => {
        pub fn fetch_fattr4_item_size(index: usize, data: &[u8]) -> Result<usize, NFSCRSInnerError> {
            match index {
                $(
                    $discriminant => {
                        deserialize_len::<$type>(data).map_err(|e| NFSCRSInnerError::InvalidArgument(format!("Failed to deserialize {}: {}", stringify!($type), e)))
                    }
                )*
                _ => Err(NFSCRSInnerError::InvalidArgument(format!("Invalid index: {}", index))),
            }
        }
    };
}

for_each_fattr4!(define_fattr4_enum);
for_each_fattr4!(define_fattr4_iterator);

pub mod fattr4_names {
    macro_rules! define_fattr4_consts {
            ($( ( $variant:ident, $type:ty, $discriminant:expr ) ),* $(,)?) => {
                $(
                    pub const $variant: usize = $discriminant;
                )*
            };
        }

    for_each_fattr4!(define_fattr4_consts);
}

// generate match case code here
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FAttr4 {
    pub attr_mask: BitMap4,
    pub attr_vals: AttrList4,
}

impl FAttr4 {
    pub fn empty_attr() -> Self {
        Self {
            attr_mask: Vec::new(),
            attr_vals: AttrList4::new(),
        }
    }

    pub fn simple_dir_attr() -> Self {
        let mode: u32 = 0o750;
        fattr4_from_mode(mode)
    }
    pub fn simple_file_attr() -> Self {
        let mode: u32 = 0o640;
        fattr4_from_mode(mode)
    }
    
    pub fn fetch_attr_raw(&self, bit_num: usize) -> Result<ByteBuf, NFSCRSInnerError> {
        let attr_list = attr_mask_to_list(&self.attr_mask);

        let target_index = bit_num as usize;
        if !attr_list.contains(&target_index) {
            return Err(NFSCRSInnerError::InvalidArgument(format!(
                "bit_num {} not found in attribute mask",
                bit_num
            )));
        }

        let mut remaining_bytes = self.attr_vals.as_slice();

        for attr_index in attr_list {
            let attr_len = fetch_fattr4_item_size(attr_index, remaining_bytes)?;

            if attr_len > remaining_bytes.len() {
                return Err(NFSCRSInnerError::InvalidArgument(format!(
                    "Invalid attribute length {} for bit_num {}",
                    attr_len, attr_index
                )));
            }

            if attr_index == target_index {
                
                return Ok(remaining_bytes[..attr_len].to_vec().into());
            }
            remaining_bytes = &remaining_bytes[attr_len..];
        }

        Err(NFSCRSInnerError::InvalidArgument(format!(
            "bit_num {} not found",
            bit_num
        )))
    }
    pub fn fetch_attr(&self, bit_num: usize) -> Result<FAttr4Type, NFSCRSInnerError> {
        let data = self.fetch_attr_raw(bit_num)?;
        FAttr4Type::from_bitnum(&data, bit_num)
    }
}

pub fn set_bitmap(bitmap: &mut BitMap4, bit_pos: usize) {
    let required_len = (bit_pos / 32) + 1;
    while bitmap.len() < required_len {
        bitmap.push(0);
    }
    bitmap[bit_pos / 32] |= 1 << (bit_pos % 32);
}
