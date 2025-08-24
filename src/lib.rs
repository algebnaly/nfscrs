#![allow(non_camel_case_types)]
#![allow(dead_code)]
use std::{
    cell::Cell,
    io::{self, Write},
    net::{SocketAddr, TcpStream},
    path::{Component, Path},
};

use crate::{
    auth::AuthType,
    nfs4types::{BitMap4, ClientId4, Count4, Offset4},
    nfscrs_types::{AbsolutePath, DirEntry},
    nfsv4_rpc_def::{NFSPROC4_COMPOUND, NFSPROC4_NULL},
    nfsv4ops::{
        CallBackClient4, Compound4Result, FAttr4, GetAttr4Args, GetAttr4Result, GetFH4Result,
        LookUp4Args, NFS4CompoundProcedure, NFSArgOp4, NFSClientId4, NFSResultOp4, NFSStat4,
        Open4Args, Open4Result, OpenConfirm4Args, OpenConfirm4Result, PutFH4Args, Read4Args,
        Read4Result, ReadDir4Args, ReadDir4Result, SetClientId4Args, SetClientId4Result,
        SetClientIdConfirm4Args, Verifier4, Write4Args, Write4Result,
    },
    oncrpc_msg::{ONCRPCMessageReader, ONCRPCMessageReaderError},
    xdr_types::Opaque,
};
use onc_rpc::{AcceptedStatus, ReplyBody, RpcMessage, auth::AuthUnixParams};
use thiserror::Error;

mod auth;
mod nfs4types;
pub mod nfscrs_types;
mod nfsv4_rpc_def;
mod nfsv4ops;
mod oncrpc_msg;
mod state;
mod xdr_types;

pub use state::*;

pub struct NFSClientBuilder {
    xid: Cell<u32>,
    auth: AuthType,
    msg_reader: ONCRPCMessageReader,
    remote_addr: SocketAddr,
}

pub struct NFSClientSession {
    xid: Cell<u32>,
    auth: AuthType,
    msg_reader: ONCRPCMessageReader,
    stream: TcpStream,
    remote_addr: SocketAddr,
    client_id: ClientId4,
}

#[derive(Debug, Error)]
pub enum NFSCRSError {
    #[error("failed to connect: {0}")]
    Connection(#[from] io::Error),
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

#[derive(Debug, Error)]
pub enum NFSCRSInnerError {
    #[error("invalied argument: {0}")]
    InvalidArgument(String),
    #[error("xdr serialization error: {0}")]
    XDRSederError(#[from] xdr_brk::Error),
    #[error("wrong message type: {0}")]
    WrongMessageType(String),
    #[error("wrong operation reply type: {0}")]
    WrongOperationReply(String),
}

impl NFSClientBuilder {
    pub fn new(uid: u32, gid: u32, remote_addr: SocketAddr) -> Self {
        Self {
            xid: Cell::new(rand::random()),
            auth: AuthType::AuthUnix(AuthUnixParams::new(
                rand::random(),
                "nfscrs".to_owned(),
                uid,
                gid,
                None,
            )),
            msg_reader: ONCRPCMessageReader::new(),
            remote_addr,
        }
    }
    pub fn test_null_call(&mut self) -> Result<(), NFSCRSError> {
        let null_call_payload: [u8; 0] = [];
        let call_msg = self.get_onc_rpc_call_message(NFSPROC4_NULL, &null_call_payload);
        let mut stream = TcpStream::connect(self.remote_addr).map_err(NFSCRSError::from)?;
        self.send_msg(call_msg, &mut stream)?;
        let reply = self.read_reply(&mut stream)?;
        if let Some(r) = reply.reply_body() {
            match r {
                onc_rpc::ReplyBody::Accepted(_) => Ok(()),
                onc_rpc::ReplyBody::Denied(denied) => {
                    Err(NFSCRSError::ReplyDenied(format!("{denied:?}")))
                }
            }
        } else {
            Err(NFSCRSError::EmptyReplyBody)
        }
    }

    fn get_onc_rpc_call_message<P: AsRef<[u8]>>(
        &mut self,
        procedure: u32,
        payload: P,
    ) -> onc_rpc::RpcMessage<String, P> {
        match self.auth {
            AuthType::AuthUnix(ref auth_unix) => onc_rpc::RpcMessage::new(
                self.pop_xid(),
                onc_rpc::MessageType::Call(onc_rpc::CallBody::new(
                    nfsv4_rpc_def::PROGRAM,
                    nfsv4_rpc_def::VERSION_NFS_V4,
                    procedure,
                    onc_rpc::auth::AuthFlavor::AuthUnix(auth_unix.clone()),
                    onc_rpc::auth::AuthFlavor::AuthNone(None),
                    payload,
                )),
            ),
            AuthType::AuthKerberos => {
                todo!("implement krb5 client")
            }
        }
    }
    fn get_onc_rpc_compound_call_message<P: AsRef<[u8]>>(
        &mut self,
        payload: P,
    ) -> onc_rpc::RpcMessage<String, P> {
        self.get_onc_rpc_call_message(NFSPROC4_COMPOUND, payload)
    }
    fn pop_xid(&self) -> u32 {
        let current_xid = self.xid.get();
        self.xid.set(current_xid.wrapping_add(1));
        current_xid
    }
    fn send_msg<P: AsRef<[u8]>>(
        &mut self,
        msg: onc_rpc::RpcMessage<String, P>,
        stream: &mut TcpStream,
    ) -> Result<(), NFSCRSError> {
        let buf = msg.serialise()?;
        stream.write_all(&buf)?;
        Ok(())
    }
    fn read_reply(
        &mut self,
        stream: &mut TcpStream,
    ) -> Result<RpcMessage<onc_rpc::Bytes, onc_rpc::Bytes>, NFSCRSError> {
        let reply = self.msg_reader.read(stream)?;
        Ok(reply)
    }
    pub fn establish_session(mut self) -> Result<NFSClientSession, NFSCRSError> {
        let mut set_client_id_cops = NFS4CompoundProcedure::new();
        let client_id = rand::random_iter().take(12).collect();
        let set_client_arg = SetClientId4Args::build(
            NFSClientId4::new(Verifier4::zero(), client_id),
            CallBackClient4::dummy_callback(),
            0,
        )?;
        let op_set_client_id = NFSArgOp4::OP_SETCLIENTID(set_client_arg);
        set_client_id_cops.add_operation(op_set_client_id);
        let payload = set_client_id_cops.to_bytes()?;
        let msg = self.get_onc_rpc_compound_call_message(payload);
        let mut stream = TcpStream::connect(self.remote_addr)?;
        self.send_msg(msg, &mut stream)?;
        let reply = self.read_reply(&mut stream)?;
        let result = read_compound_result(&reply)?;
        if !result.is_status_ok() {
            return Err(NFSCRSError::NFSStatError(result.status));
        }

        let client_id: ClientId4;
        let set_client_id_confirm: Verifier4;
        if let Some(NFSResultOp4::OP_SETCLIENTID(res)) = result.resarray.last()
            && let SetClientId4Result::NFS4_OK(res_ok) = res
        {
            client_id = res_ok.client_id;
            set_client_id_confirm = res_ok.set_client_id_confirm.clone();
        } else {
            return Err(NFSCRSError::OperationError(format!(
                "set_client_id operation failed: {result:?}",
            )));
        }
        let set_client_id_confirm_args = SetClientIdConfirm4Args {
            client_id,
            setclientid_confirm: set_client_id_confirm,
        };
        let mut cops = NFS4CompoundProcedure::new();
        let op_set_client_id_confirm =
            NFSArgOp4::OP_SETCLIENTID_CONFIRM(set_client_id_confirm_args);
        cops.add_operation(op_set_client_id_confirm);
        let payload = cops.to_bytes()?;
        let cops_msg = self.get_onc_rpc_compound_call_message(payload);
        self.send_msg(cops_msg, &mut stream)?;
        let reply = self.read_reply(&mut stream)?;
        let result = read_compound_result(&reply)?;
        if !result.is_status_ok() {
            return Err(NFSCRSError::NFSStatError(result.status));
        }

        let Some(NFSResultOp4::OP_SETCLIENTID_CONFIRM(res)) = result.resarray.last() else {
            return Err(NFSCRSError::OperationError(format!(
                "set_client_id operation failed: {result:?}",
            )));
        };

        if !matches!(res.status, NFSStat4::NFS4_OK) {
            return Err(NFSCRSError::OperationError(format!(
                "set_client_id operation failed: {result:?}",
            )));
        }

        Ok(NFSClientSession {
            xid: Cell::new(self.pop_xid()),
            auth: self.auth,
            msg_reader: self.msg_reader,
            stream,
            remote_addr: self.remote_addr,
            client_id,
        })
    }
}

pub fn read_reply_body<T: AsRef<[u8]>, P: AsRef<[u8]>>(
    reply_message: &RpcMessage<T, P>,
) -> Result<&P, NFSCRSInnerError> {
    if let Some(body) = reply_message.reply_body()
        && let ReplyBody::Accepted(accept) = body
        && let AcceptedStatus::Success(payload) = accept.status()
    {
        Ok(payload)
    } else {
        Err(NFSCRSInnerError::WrongMessageType(
            "expected reply an accepted message".to_owned(),
        ))
    }
}

pub fn read_compound_result<T: AsRef<[u8]>, P: AsRef<[u8]>>(
    reply_message: &RpcMessage<T, P>,
) -> Result<Compound4Result, NFSCRSInnerError> {
    let reply_message = read_reply_body(reply_message)?;
    xdr_brk::from_bytes(reply_message.as_ref()).map_err(NFSCRSInnerError::from)
}

impl NFSClientSession {
    fn send_msg<P: AsRef<[u8]>>(
        &mut self,
        msg: onc_rpc::RpcMessage<String, P>,
    ) -> Result<(), NFSCRSError> {
        let buf = msg.serialise().unwrap();
        let stream = &mut self.stream;
        stream.write(&buf).map_err(|e| {
            NFSCRSError::SendMessage(format!("failed to write to TcpStream: {e:?}"))
        })?;
        Ok(())
    }
    fn read_reply(&mut self) -> Result<RpcMessage<onc_rpc::Bytes, onc_rpc::Bytes>, NFSCRSError> {
        let stream = &mut self.stream;
        // stream.
        let reply = self.msg_reader.read(stream)?;
        Ok(reply)
    }
    fn pop_xid(&self) -> u32 {
        let current_xid = self.xid.get();
        self.xid.set(current_xid.wrapping_add(1));
        current_xid
    }
    fn get_onc_rpc_call_message<P: AsRef<[u8]>>(
        &mut self,
        procedure: u32,
        payload: P,
    ) -> onc_rpc::RpcMessage<String, P> {
        match self.auth {
            AuthType::AuthUnix(ref auth_unix) => onc_rpc::RpcMessage::new(
                self.pop_xid(),
                onc_rpc::MessageType::Call(onc_rpc::CallBody::new(
                    nfsv4_rpc_def::PROGRAM,
                    nfsv4_rpc_def::VERSION_NFS_V4,
                    procedure,
                    onc_rpc::auth::AuthFlavor::AuthUnix(auth_unix.clone()),
                    onc_rpc::auth::AuthFlavor::AuthNone(None),
                    payload,
                )),
            ),
            AuthType::AuthKerberos => {
                todo!("implement krb5 client")
            }
        }
    }

    fn get_onc_rpc_compound_call_message<P: AsRef<[u8]>>(
        &mut self,
        payload: P,
    ) -> onc_rpc::RpcMessage<String, P> {
        self.get_onc_rpc_call_message(NFSPROC4_COMPOUND, payload)
    }

    fn read_cops_result(&mut self) -> Result<Compound4Result, NFSCRSError> {
        let reply = self.read_reply()?;
        read_compound_result(&reply).map_err(|e| e.into())
    }

    pub fn read_dir(&mut self) {}
    pub fn lookup(&mut self, _path: &str) {}
    pub fn get_current_fh(&mut self) {}
    pub fn get_attr(&mut self, attr_list: BitMap4) -> Result<FAttr4, NFSCRSError> {
        let mut cops = NFS4CompoundProcedure::new();
        cops.add_operation(NFSArgOp4::OP_GETATTR(GetAttr4Args::new(attr_list)));
        let result = self.send_cops_and_get_result(&cops)?;
        if !result.is_status_ok() {
            return Err(NFSCRSError::ReplyDenied("status is not ok".to_owned()));
        } // is last status is ok, then all operation are ok
        let Some(NFSResultOp4::OP_GETATTR(GetAttr4Result::NFS4_OK(res))) = result.resarray.last()
        else {
            return Err(NFSCRSError::EmptyReplyBody);
        };
        Ok(res.obj_attributes.clone())
    }
    pub fn test_get_attr(&mut self) -> Result<FAttr4, NFSCRSError> {
        let mut cops = NFS4CompoundProcedure::new();
        cops.add_operation(NFSArgOp4::OP_PUTROOTFH);
        cops.add_operation(NFSArgOp4::OP_GETATTR(GetAttr4Args::new(vec![1])));
        let result = self.send_cops_and_get_result(&cops)?;
        if !result.is_status_ok() {
            //TODO: need futher check whats going wrong
            return Err(NFSCRSError::ReplyDenied("status is not ok".to_owned()));
        }
        let mut resarray = result.resarray;
        let NFSResultOp4::OP_GETATTR(GetAttr4Result::NFS4_OK(res)) =
            resarray.pop().ok_or(NFSCRSError::EmptyReplyBody)?
        else {
            return Err(NFSCRSError::OperationError("wrong reply type".to_owned()));
        };
        Ok(res.obj_attributes)
    }
    pub fn put_root_fh(&mut self) -> Result<(), NFSCRSError> {
        let mut cops = NFS4CompoundProcedure::new();
        cops.add_operation(NFSArgOp4::OP_PUTROOTFH);
        let result = self.send_cops_and_get_result(&cops)?;
        if !result.is_status_ok() {
            return Err(NFSCRSError::ReplyDenied("status is not ok".to_owned()));
        }

        let Some(put_root_fh_result) = result.resarray.last() else {
            return Err(NFSCRSError::EmptyReplyBody);
        };
        match put_root_fh_result {
            NFSResultOp4::OP_PUTROOTFH(_) => {}
            _ => {
                return Err(NFSCRSError::OperationError(
                    "returns wrong operation type".to_owned(),
                ));
            }
        }
        Ok(())
    }
    fn send_cops_and_get_result(
        &mut self,
        cops: &NFS4CompoundProcedure,
    ) -> Result<Compound4Result, NFSCRSError> {
        let payload = cops.to_bytes()?;
        let msg = self.get_onc_rpc_compound_call_message(payload);
        self.send_msg(msg)?;
        self.read_cops_result()
    }
    pub fn list_dir(&mut self, path: &AbsolutePath) -> Result<Vec<DirEntry>, NFSCRSError> {
        let mut cops = NFS4CompoundProcedure::new();
        push_lookup_ops(&mut cops, path)?;

        let readdir_args = ReadDir4Args::start_read(1 << 20, 1024, vec![1]);
        cops.add_operation(NFSArgOp4::OP_READDIR(readdir_args));
        let mut result = self.send_cops_and_get_result(&cops)?;
        if !result.is_status_ok() {
            return Err(NFSCRSError::OperationError("readdir failed!".to_owned()));
        }
        let Some(NFSResultOp4::OP_READDIR(ReadDir4Result::NFS4_OK(res))) = result.resarray.pop()
        else {
            return Err(NFSCRSError::OperationError(
                "results wrong operation type".to_owned(),
            ));
        };
        Ok(res.build_entries())
    }
    pub fn open(
        &mut self,
        path: &AbsolutePath,
        open_options: OpenOptions,
    ) -> Result<OpeningFile, NFSCRSError> {
        let mut cops = NFS4CompoundProcedure::new();

        let (dirs, filename) = split_path(path)?;

        push_lookup_ops(&mut cops, &dirs)?;
        let open_args = Open4Args::with_open_options(self, filename, open_options);

        let open_owner_seq_id = open_args.seq_id;
        let share_access = open_args.share_access;
        let share_deny = open_args.share_deny;
        let open_flag = open_args.open_how.clone();

        cops.add_operation(NFSArgOp4::OP_OPEN(open_args));
        cops.add_operation(NFSArgOp4::OP_GETFH);
        let result = self.send_cops_and_get_result(&cops)?;
        if !result.is_status_ok() {
            return Err(NFSCRSError::NFSStatError(result.status));
        }

        let mut res_array = result.resarray;

        // since rresult.is_status_ok() is true, than all operation are success.
        // unwrap() below are all safe.
        let get_fh_result = res_array.pop().unwrap();
        let NFSResultOp4::OP_GETFH(GetFH4Result::NFS4_OK(get_fh_result_ok)) = get_fh_result else {
            return Err(
                NFSCRSInnerError::WrongMessageType("expecting GetFH4Result".to_owned()).into(),
            );
        };
        let open_result = res_array.pop().unwrap();
        let NFSResultOp4::OP_OPEN(Open4Result::NFS4_OK(open_result_ok)) = open_result else {
            return Err(
                NFSCRSInnerError::WrongMessageType("expecting Open4Result".to_owned()).into(),
            );
        };

        let opening_file = OpeningFileBuilder {
            get_fh_result: get_fh_result_ok,
            open_result: open_result_ok,
            share_access,
            share_deny,
            open_owner_seq_id,
            open_flag,
            path: path.clone().into_owned(),
        }
        .build()?;
        Ok(opening_file)
    }

    pub fn open_confirm(&mut self, opening_file: OpeningFile) -> Result<OpenedFile, NFSCRSError> {
        let mut cops = NFS4CompoundProcedure::new();
        cops.add_operation(NFSArgOp4::OP_PUTFH(PutFH4Args {
            object: opening_file.file_handle.clone(),
        }));

        let mut open_confirm_args = OpenConfirm4Args {
            open_stateid: opening_file.state_id.clone(),
            seq_id: opening_file.open_owner_seq_id + 1,
        };

        open_confirm_args.open_stateid.seq_id = open_confirm_args.seq_id;

        cops.add_operation(NFSArgOp4::OP_OPEN_CONFIRM(open_confirm_args));

        let result = self.send_cops_and_get_result(&cops)?;
        if !result.is_status_ok() {
            return Err(NFSCRSError::NFSStatError(result.status));
        }
        let mut res_array = result.resarray;
        let open_confirm_result = res_array.pop().unwrap();

        let NFSResultOp4::OP_OPEN_CONFIRM(OpenConfirm4Result::NFS4_OK(open_confirm_result_ok)) =
            open_confirm_result
        else {
            return Err(NFSCRSInnerError::WrongMessageType(
                "expecting OpenConfirm4Result".to_owned(),
            )
            .into());
        };

        let opened_file = OpenedFile {
            file_handle: opening_file.file_handle,
            delegation: opening_file.delegation,
            state_id: open_confirm_result_ok.open_stateid,
            share_access: opening_file.share_access,
            share_deny: opening_file.share_deny,
            offset: 0,
            path: opening_file.path,
        };
        Ok(opened_file)
    }
    pub fn close(&mut self) {}

    pub fn read(
        &mut self,
        opened_file: &mut OpenedFile,
        count: usize,
    ) -> Result<ReadResult, NFSCRSError> {
        let mut cops = NFS4CompoundProcedure::new();
        cops.add_operation(NFSArgOp4::OP_PUTFH(PutFH4Args {
            object: opened_file.file_handle.clone(),
        }));
        cops.add_operation(NFSArgOp4::OP_READ(Read4Args {
            state_id: opened_file.state_id.clone(),
            offset: opened_file.offset as Offset4,
            count: count as Count4,
        }));
        let result = self.send_cops_and_get_result(&cops)?;
        if !result.is_status_ok() {
            return Err(NFSCRSError::NFSStatError(result.status));
        }
        let mut res_array = result.resarray;
        let read_result = res_array.pop().unwrap();

        let NFSResultOp4::OP_READ(Read4Result::NFS4_OK(read_result_ok)) = read_result else {
            return Err(
                NFSCRSInnerError::WrongMessageType("expecting Read4Result".to_owned()).into(),
            );
        };

        let read_count = read_result_ok.data.len();
        opened_file.offset += read_count;

        Ok(read_result_ok.into())
    }
    pub fn write(
        &mut self,
        opened_file: &mut OpenedFile,
        data: &[u8],
    ) -> Result<WriteResult, NFSCRSError> {
        let mut cops = NFS4CompoundProcedure::new();
        cops.add_operation(NFSArgOp4::OP_PUTFH(PutFH4Args {
            object: opened_file.file_handle.clone(),
        }));
        cops.add_operation(NFSArgOp4::OP_WRITE(Write4Args {
            state_id: opened_file.state_id.clone(),
            offset: opened_file.offset as u64,
            stable: nfsv4ops::StableHow4::UNSTABLE4,
            data: Opaque::from(data),
        }));
        let result = self.send_cops_and_get_result(&cops)?;
        if !result.is_status_ok() {
            return Err(NFSCRSError::NFSStatError(result.status));
        }
        let mut res_array = result.resarray;
        let write_result = res_array.pop().unwrap();

        let NFSResultOp4::OP_WRITE(Write4Result::NFS4_OK(write_result_ok)) = write_result else {
            return Err(
                NFSCRSInnerError::WrongMessageType("expecting Read4Result".to_owned()).into(),
            );
        };

        opened_file.offset += write_result_ok.count as usize;
        Ok(WriteResult {
            count: write_result_ok.count,
            committed: write_result_ok.committed,
            writeverf: write_result_ok.writeverf,
        })
    }
    pub fn mkdir(&mut self, _path: AbsolutePath, _parents: bool, _exists_ok: bool) {
        todo!()
    }
}

pub fn push_lookup_ops(
    cops: &mut NFS4CompoundProcedure,
    path: &AbsolutePath,
) -> Result<(), NFSCRSError> {
    cops.add_operation(NFSArgOp4::OP_PUTROOTFH);
    for c in path.components() {
        if matches!(c, Component::Normal(_)) {
            let c_name = c
                .as_os_str()
                .to_str()
                .ok_or(NFSCRSInnerError::InvalidArgument(
                    "os_str is not utf8 str".to_owned(),
                ))?
                .to_owned();
            cops.add_operation(NFSArgOp4::OP_LOOKUP(LookUp4Args::new(Opaque::from(
                c_name.as_bytes(),
            ))));
        }
    }
    Ok(())
}

pub fn split_path<'a, 'p>(
    path: &'a AbsolutePath<'p>,
) -> Result<(AbsolutePath<'a>, &'a str), NFSCRSInnerError> {
    let filename = path
        .file_name()
        .ok_or(NFSCRSInnerError::InvalidArgument(format!(
            "path is not file name: {path:?}"
        )))?;
    let parent = path.parent().unwrap_or(Path::new("/"));
    Ok((
        AbsolutePath::try_from(parent).unwrap(),
        filename.to_str().unwrap(),
    ))
}
