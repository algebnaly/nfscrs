use xdr_brk::from_bytes;

use crate::{fattr4::FAttr4, nfs4_types::{AttrList4, NFSFType4}, NFSCRSInnerError, OpenOptions};

pub(crate) fn attr_mask_to_list(attr_mask: &[u32]) -> Vec<usize> {
    let mut result = Vec::new();
    for (i, a) in attr_mask.iter().enumerate() {
        for b in 0..32 {
            if a & (1 << b) != 0 {
                result.push(i * 32 + b);
            }
        }
    }
    result
}

pub(crate) fn is_dir(fattr4: &FAttr4) -> Result<bool, NFSCRSInnerError> {
    let attr_bytes = fattr4.fetch_attr_raw(1)?;
    let file_type: NFSFType4 = from_bytes(&attr_bytes)?;
    Ok(matches!(file_type, NFSFType4::NF4DIR))
}

pub(crate) fn fattr4_from_mode(mode: u32) -> FAttr4{
    let mut attr_vals = AttrList4::new();
    attr_vals.extend_from_slice(&mode.to_be_bytes());
    FAttr4{
        attr_mask: vec![0, 2, //  bit 33 MODE4
        ],
        attr_vals
    }
}

pub(crate) fn fattr4_from_options(opt: OpenOptions) -> FAttr4{
    let mut mode = 0o000;
    if opt.read{
        mode |= 0o400;
    }
    if opt.write{
        mode |= 0o200;
    }
    fattr4_from_mode(mode)
}