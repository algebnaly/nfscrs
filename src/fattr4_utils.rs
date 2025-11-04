use std::collections::HashMap;

use serde_bytes::ByteBuf;
use xdr_brk::from_bytes;

use crate::{
    NFSCRSInnerError, OpenOptions,
    fattr4::{FAttr4, fattr4_names},
    nfs4_types::{AttrList4, NFSFType4},
};

#[derive(Debug, Clone)]
pub struct FAttr4Builder {
    attr_list: HashMap<usize, Vec<u8>>,
}

impl FAttr4Builder {
    pub fn new() -> Self {
        Self {
            attr_list: HashMap::new(),
        }
    }

    pub fn build(self) -> FAttr4 {
        let mut attr_bit_nums: Vec<usize> = self.attr_list.keys().copied().collect();
        attr_bit_nums.sort();
        let mut attr_vals: Vec<u8> = Vec::new();
        for b in &attr_bit_nums {
            if let Some(v) = self.attr_list.get(b) {
                attr_vals.extend_from_slice(v);
            }
        }
        let attr_mask = bit_nums_to_attr_mask(&attr_bit_nums);
        FAttr4 {
            attr_mask,
            attr_vals: ByteBuf::from(attr_vals),
        }
    }

    pub fn from_fattr4(fattr4: &FAttr4) -> Result<Self, NFSCRSInnerError> {
        let keys = attr_mask_to_list(&fattr4.attr_mask); // already sorted here
        let attr_vals = fattr4.fetch_attr_vals_raw(&keys)?;
        let mut attr_list: HashMap<usize, Vec<u8>> = HashMap::new();

        // keys and attr_vals are gurateed to be the same length
        for (k, attr) in keys.into_iter().zip(attr_vals.into_iter()) {
            attr_list.insert(k.clone(), attr);
        }
        Ok(FAttr4Builder { attr_list })
    }

    pub fn set_file_size(&mut self, size: u64) -> &mut Self {
        self.attr_list
            .insert(fattr4_names::FATTR4_SIZE, size.to_be_bytes().to_vec());
        self
    }

    pub fn set_open_options(&mut self, opt: &OpenOptions) -> &mut Self {
        self.attr_list.insert(
            fattr4_names::FATTR4_MODE,
            mode_num(opt).to_be_bytes().to_vec(),
        );
        self
    }
}

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

pub(crate) fn bit_nums_to_attr_mask(bit_nums: &[usize]) -> Vec<u32> {
    let mut attr_mask: Vec<u32> = Vec::new();
    for b in bit_nums {
        let p_num = b / 32;
        let attr_mask_len = attr_mask.len();
        let zero_needed = p_num + 1 - attr_mask_len;
        for _ in 0..zero_needed {
            attr_mask.push(0);
        }
        let left_shift_num = b % 32;
        attr_mask[p_num] |= 1 << left_shift_num;
    }
    attr_mask
}

pub(crate) fn is_dir(fattr4: &FAttr4) -> Result<bool, NFSCRSInnerError> {
    let attr_bytes = fattr4.fetch_attr_raw(1)?;
    let file_type: NFSFType4 = from_bytes(&attr_bytes)?;
    Ok(matches!(file_type, NFSFType4::NF4DIR))
}

pub(crate) fn fattr4_from_file_mode(mode: u32) -> FAttr4 {
    let mut attr_vals = AttrList4::new();
    attr_vals.extend_from_slice(&mode.to_be_bytes());
    FAttr4 {
        attr_mask: vec![
            0, 2, //  bit 33 MODE4
        ],
        attr_vals,
    }
}

pub(crate) fn fattr4_from_options(opt: &OpenOptions) -> FAttr4 {
    let mode = mode_num(opt);
    let fattr4 = fattr4_from_file_mode(mode);
    fattr4
}

pub(crate) fn mode_num(opt: &OpenOptions) -> u32 {
    let mut mode = 0o000; // TODO: use constants instead of hard code here.
    if opt.read {
        mode |= 0o400;
    }
    if opt.write {
        mode |= 0o200;
    }
    mode
}
