use std::sync::PoisonError;

use crate::{nfsv4_ops::NFSStat4, oncrpc_msg::ONCRPCMessageReaderError};

#[derive(Debug, thiserror::Error)]
pub enum NFSCRSError {
    #[error("failed to connect: {0}")]
    Connection(#[from] std::io::Error),
    #[error("failed to read message: {0}")]
    ReadMessage(#[from] ONCRPCMessageReaderError),
    #[error("failed to write message: {0}")]
    SendMessage(String),
    #[error("permission error: {0}")]
    Permission(String),
    #[error("ONC RPC reply was denied: {0}")]
    ReplyDenied(String),
    #[error("empty reply body")]
    EmptyReplyBody,
    #[error("NFSStat error: {0:?}")]
    NFSStatError(NFSStat4),
    #[error("NFSCRS InnerError: {0}")]
    InnerError(#[from] NFSCRSInnerError),
    #[error("OperationError: {0}")]
    OperationError(String),
}

#[derive(Debug, thiserror::Error)]
pub enum NFSCRSInnerError {
    #[error("invalied argument: {0}")]
    InvalidArgument(String),
    #[error("xdr serialization error: {0}")]
    XDRSederError(#[from] xdr_brk::Error),
    #[error("wrong message type: {0}")]
    WrongMessageType(String),
    #[error("wrong operation reply type: {0}")]
    WrongOperationReply(String),
    #[error("failed to lock: {0}")]
    PoisonedMutex(String),
    #[error("illegal state: {0}")]
    IllegalState(String),
}

impl<T> From<PoisonError<T>> for NFSCRSInnerError {
    fn from(e: PoisonError<T>) -> Self {
        NFSCRSInnerError::PoisonedMutex(e.to_string())
    }
}
