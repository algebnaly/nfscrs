use onc_rpc::{Bytes, Error as ONCRPCError, RpcMessage};
use std::io;
use std::io::Read;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ONCRPCMessageReaderError {
    #[error("failed to read from tcp")]
    StreamReadError(#[from] io::Error),

    #[error("failed to parse rpc message")]
    MessageParseError(#[from] ONCRPCError),
}

pub struct ONCRPCMessageReader {
    fragment_parts_buf: Vec<u8>, // imcomplete fragment goes here
    message_parts_buf: Vec<u8>,  // imcomplete message goes here
}

impl ONCRPCMessageReader {
    pub fn new() -> Self {
        Self {
            fragment_parts_buf: Vec::new(),
            message_parts_buf: Vec::new(),
        }
    }
    /// Read a RpcMessage, blocking
    pub fn read<R: Read>(
        &mut self,
        stream: &mut R,
    ) -> Result<RpcMessage<Bytes, Bytes>, ONCRPCMessageReaderError> {
        // First, check whether the data in self.buf can form a complete RpcMessage
        let mut temp_buf = [0u8; 256];
        const RM_LEN: usize = 4; //Record Marking Length in bytes
        const LAST_FRAG_FLAG: u8 = 0b1000_0000;
        loop {
            if self.fragment_parts_buf.len() >= RM_LEN {
                // check whether self.fragment_parts_buf has enough bytes to form a fragment,
                // and check if current fragment is last fragment
                let mut fragment_len_bytes: [u8; RM_LEN] =
                    self.fragment_parts_buf[..4].try_into().unwrap();
                let is_last_fragment = (fragment_len_bytes[0] & LAST_FRAG_FLAG) != 0;
                fragment_len_bytes[0] &= !LAST_FRAG_FLAG; // clear LAST_FRAG_FLAG
                let fragment_len = u32::from_be_bytes(fragment_len_bytes);
                if self.fragment_parts_buf.len() >= fragment_len as usize + RM_LEN {
                    self.message_parts_buf
                        .extend(self.fragment_parts_buf[..RM_LEN + fragment_len as usize].iter());
                    self.fragment_parts_buf
                        .drain(..RM_LEN + fragment_len as usize);
                    if is_last_fragment {
                        let msg_result =
                            RpcMessage::try_from(Bytes::copy_from_slice(&self.message_parts_buf))
                                .map_err(ONCRPCMessageReaderError::from);
                        self.message_parts_buf.clear(); //we need clear message_parts_buf here
                        return msg_result;
                    }
                }
            }
            //read more data
            let count = stream
                .read(&mut temp_buf)
                .map_err(ONCRPCMessageReaderError::from)?;
            if count == 0 {
                // this is necessary for if Stream is closed, it will return Ok(0) rather than Err,
                return Err(
                    io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed").into(),
                );
            }
            self.fragment_parts_buf.extend(temp_buf[..count].iter());
        }
    }
}
