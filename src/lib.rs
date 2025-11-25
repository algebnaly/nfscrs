#![allow(non_camel_case_types)]
#![allow(dead_code)]
use std::{
    cell::Cell,
    io::Write,
    net::{SocketAddr, TcpStream},
    os::unix::ffi::OsStrExt,
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
};

use crate::{
    auth::AuthType,
    constants::{READDIR_DEFAULT_ATTR, READDIR_MAX_COUNT},
    fattr4::FAttr4,
    nfs4_types::{BitMap4, ClientId4, Count4, NFSFH4, Offset4},
    nfscrs_error::{NFSCRSError, NFSCRSInnerError},
    nfscrs_types::{AbsolutePath, DirEntry},
    nfsv4_ops::{
        CallBackClient4, Close4Args, Close4Result, Compound4Result, Create4Args, CreateType4,
        GetAttr4Args, GetAttr4Result, GetFH4Result, LookUp4Args, NFS4CompoundProcedure, NFSArgOp4,
        NFSClientId4, NFSResultOp4, NFSStat4, Open4Args, Open4Result, OpenConfirm4Args,
        OpenConfirm4Result, PutFH4Args, Read4Args, Read4Result, ReadDir4Args, ReadDir4Result,
        SetAttr4Args, SetClientId4Args, SetClientId4Result, SetClientIdConfirm4Args, StateId4,
        Verifier4, Write4Args, Write4Result,
    },
    nfsv4_rpc_def::{NFSPROC4_COMPOUND, NFSPROC4_NULL},
    oncrpc_msg::ONCRPCMessageReader,
    xdr_types::Opaque,
};
use onc_rpc::{AcceptedStatus, ReplyBody, RpcMessage, auth::AuthUnixParams};
use serde_bytes::ByteBuf;

mod auth;
mod constants;
pub mod fattr4;
pub mod fattr4_utils;
pub mod nfs4_open_owner;
pub mod nfs4_types;
pub mod nfs4_utils;
pub mod nfscrs_error;
pub mod nfscrs_types;
pub mod nfs4_open;
mod nfsv4_ops;
mod nfsv4_rpc_def;
mod oncrpc_msg;
mod simple_api;
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
    open_owner: crate::nfs4_open_owner::OpenOwner,
    open_owner_lock: Arc<Mutex<()>>,
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
            open_owner: crate::nfs4_open_owner::OpenOwner {
                owner: ByteBuf::from(b"simple_open"),
                seq_id: 0,
            },
            open_owner_lock: Arc::new(Mutex::new(())),
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
    pub fn get_attr(
        &mut self,
        path: &AbsolutePath,
        attr_list: BitMap4,
    ) -> Result<FAttr4, NFSCRSError> {
        let mut cops = NFS4CompoundProcedure::new();
        push_lookup_ops(&mut cops, path)?;
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

    pub fn list_dir_path(
        &mut self,
        path: &AbsolutePath,
    ) -> Result<Vec<AbsolutePath<'static>>, NFSCRSError> {
        self.list_dir(path).map(|v| {
            v.into_iter()
                .map(|de| {
                    path.join(PathBuf::from(String::from_utf8_lossy(&de.name).to_string()))
                        .try_into()
                })
                .filter_map(|e| e.ok())
                .collect()
        })
    }

    pub fn list_dir(&mut self, path: &AbsolutePath) -> Result<Vec<DirEntry>, NFSCRSError> {
        let mut cops = NFS4CompoundProcedure::new();

        let mut readdir_args = ReadDir4Args::start_read(
            READDIR_MAX_COUNT,
            READDIR_MAX_COUNT,
            READDIR_DEFAULT_ATTR.to_vec(),
        );
        let mut dir_entry_list: Vec<DirEntry> = Vec::new();
        loop {
            cops.argarray.clear();
            push_lookup_ops(&mut cops, path)?;
            cops.add_operation(NFSArgOp4::OP_READDIR(readdir_args));

            let mut result = self.send_cops_and_get_result(&cops)?;
            if !result.is_status_ok() {
                return Err(NFSCRSError::OperationError("readdir failed!".to_owned()));
            }
            let Some(NFSResultOp4::OP_READDIR(ReadDir4Result::NFS4_OK(res))) =
                result.resarray.pop()
            else {
                return Err(NFSCRSError::OperationError(
                    "results wrong operation type".to_owned(),
                ));
            };
            let next_cookie_verf = res.cookie_verf.clone();
            let entries_with_cookie = res.build_entries();

            dir_entry_list.extend_from_slice(&entries_with_cookie.0);

            if res.readdir_complete() {
                break;
            }

            if let Some(cookie) = entries_with_cookie.1 {
                readdir_args = ReadDir4Args {
                    cookie,
                    cookie_verf: next_cookie_verf,
                    dircount: READDIR_MAX_COUNT,
                    maxcount: READDIR_MAX_COUNT,
                    attr_request: READDIR_DEFAULT_ATTR.to_vec(),
                };
            } else {
                break;
            }
        }
        Ok(dir_entry_list)
    }

    // TODO handle seq_id outside open and open_confirm method
    pub fn open(
        &mut self,
        path: &AbsolutePath,
        open_options: OpenOptions,
    ) -> Result<OpenedFile, NFSCRSError> {
        let mut cops = NFS4CompoundProcedure::new();

        let (dirs, filename) = split_path(path)?;

        push_lookup_ops(&mut cops, &dirs)?;

        let seq_id = self.open_owner.seq_id;
        println!("open: seq_id: {seq_id}");
        self.open_owner.seq_id += 1;

        let open_args = Open4Args::with_open_options(self, filename, seq_id, open_options);

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
        
        println!("open_result_ok: {:?}", open_result_ok.state_id);

        let opening_file = OpenedFileBuilder {
            get_fh_result: get_fh_result_ok,
            open_result: open_result_ok,
            share_access,
            share_deny,
            open_owner_seq_id: seq_id,
            path: path.clone().into_owned(),
        }
        .build()?;
        Ok(opening_file)
    }

    pub fn open_confirm(&mut self, mut opened_file: OpenedFile) -> Result<OpenedFile, NFSCRSError> {
        let mut cops = NFS4CompoundProcedure::new();
        cops.add_operation(NFSArgOp4::OP_PUTFH(PutFH4Args {
            object: opened_file.file_handle.clone(),
        }));

        let seq_id = self.open_owner.seq_id;
        println!("open_confirm seq_id: {}", seq_id);
        self.open_owner.seq_id += 1;
        
        println!("state_id.seq_id: {}", opened_file.state_id.seq_id);
        let open_confirm_args = OpenConfirm4Args {
            open_stateid: opened_file.state_id.clone(),
            seq_id,
        };

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
        
        opened_file.state_id = open_confirm_result_ok.open_stateid;
        
        Ok(opened_file)
    }

    pub fn close(&mut self, opened_file: &mut OpenedFile) -> Result<StateId4, NFSCRSError> {
        let seq_id = self.open_owner.seq_id;
        self.open_owner.seq_id += 1;

        let mut cops = NFS4CompoundProcedure::new();
        cops.add_operation(NFSArgOp4::OP_PUTFH(PutFH4Args {
            object: opened_file.file_handle.clone(),
        }));
        cops.add_operation(NFSArgOp4::OP_CLOSE(Close4Args {
            seq_id,
            open_state_id: opened_file.state_id.clone(),
        }));
        let result = self.send_cops_and_get_result(&cops)?;
        if !result.is_status_ok() {
            return Err(NFSCRSError::NFSStatError(result.status));
        }
        let mut res_array = result.resarray;
        let close_result = res_array.pop().unwrap();
        let NFSResultOp4::OP_CLOSE(Close4Result::NFS4_OK(close_result_seq_id)) = close_result
        else {
            return Err(
                NFSCRSInnerError::WrongMessageType("expecting Close4Result".to_owned()).into(),
            );
        };
        Ok(close_result_seq_id)
    }

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
            stable: nfsv4_ops::StableHow4::UNSTABLE4,
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
                NFSCRSInnerError::WrongMessageType("expecting Write4Result".to_owned()).into(),
            );
        };

        opened_file.offset += write_result_ok.count as usize;
        Ok(WriteResult {
            count: write_result_ok.count,
            committed: write_result_ok.committed,
            writeverf: write_result_ok.writeverf,
        })
    }

    pub fn set_file_attr(
        &mut self,
        path: &AbsolutePath,
        fattr4: FAttr4,
    ) -> Result<BitMap4, NFSCRSError> {
        let opening_file = self.open(path, OpenOptions::new().write(true))?;
        let opened_file = self.open_confirm(opening_file)?;
        let bitmap = self.set_attr(&opened_file.file_handle, &fattr4, &opened_file.state_id)?;
        //TODO: need a close operation here
        Ok(bitmap)
    }

    pub fn set_attr(
        &mut self,
        fh: &NFSFH4,
        fattr4: &FAttr4,
        state_id: &StateId4,
    ) -> Result<BitMap4, NFSCRSError> {
        let mut cops = NFS4CompoundProcedure::new();
        cops.add_operation(NFSArgOp4::OP_PUTFH(PutFH4Args { object: fh.clone() }));
        let set_attr_op = SetAttr4Args {
            state_id: state_id.clone(),
            obj_attributes: fattr4.clone(),
        };
        cops.add_operation(NFSArgOp4::OP_SETATTR(set_attr_op));
        let mut result = self.send_cops_and_get_result(&cops)?;
        if !result.is_status_ok() {
            return Err(NFSCRSError::NFSStatError(result.status));
        }

        let bitmap = if let Some(NFSResultOp4::OP_SETATTR(set_attr_result)) = result.resarray.pop()
        {
            if !matches!(set_attr_result.status, NFSStat4::NFS4_OK) {
                return Err(NFSCRSError::NFSStatError(set_attr_result.status));
            }
            set_attr_result.attrs_set
        } else {
            return Err(NFSCRSError::EmptyReplyBody);
        };
        Ok(bitmap)
    }

    fn check_is_dir(&mut self, path: &AbsolutePath) -> Result<bool, NFSCRSError> {
        let mut cops = NFS4CompoundProcedure::new();
        push_lookup_and_getattr_ops(&mut cops, &path, GetAttr4Args::filetype())?;
        let mut result = self.send_cops_and_get_result(&cops)?;
        if !result.is_status_ok() {
            return Err(NFSCRSError::NFSStatError(result.status));
        }

        if let Some(NFSResultOp4::OP_GETATTR(GetAttr4Result::NFS4_OK(getattr_result))) =
            result.resarray.pop()
        {
            let fattr = getattr_result.obj_attributes;
            fattr4_utils::is_dir(&fattr).map_err(|e| e.into())
        } else {
            Err(NFSCRSError::OperationError(format!(
                "failed to getattr: {:?}",
                path
            )))
        }
    }

    fn path_exist_part(
        &mut self,
        path: &AbsolutePath,
    ) -> Result<AbsolutePath<'static>, NFSCRSError> {
        let mut cops = NFS4CompoundProcedure::new();
        push_lookup_ops(&mut cops, &path)?;
        let result = self.send_cops_and_get_result(&cops)?;
        let prev_len = cops.argarray.len();
        let succ_len = if result.is_status_ok() {
            prev_len
        } else {
            result.resarray.len() - 1
        };
        if succ_len == 0 {
            return Err(NFSCRSError::OperationError(
                "failed to put root fh".to_string(),
            ));
        }
        let new_path = construct_path_with_n_components(path, succ_len)?;
        Ok(new_path)
    }

    pub fn mkdir(
        &mut self,
        path: &AbsolutePath,
        parents: bool,
        exists_ok: bool,
    ) -> Result<(), NFSCRSError> {
        if path.is_root() {
            if self.check_is_dir(&path)? {
                if exists_ok {
                    return Ok(());
                }
                return Err(
                    NFSCRSInnerError::InvalidArgument("target dir exists".to_string()).into(),
                );
            } else {
                return Err(NFSCRSInnerError::InvalidArgument(
                    "target path exists but is not a directory".to_string(),
                )
                .into());
            }
        }

        let exist_part = self.path_exist_part(&path)?;
        if &exist_part == path {
            if !exists_ok {
                return Err(
                    NFSCRSInnerError::InvalidArgument("target path exists".to_string()).into(),
                );
            } else {
                if self.check_is_dir(&path)? {
                    return Ok(());
                } else {
                    return Err(NFSCRSInnerError::InvalidArgument(
                        "target path exists but is not a directory".to_string(),
                    )
                    .into());
                }
            }
        }

        if let Some(parent) = path.parent() {
            if parent == exist_part.as_ref() {
                return self.create_dir_inner(path, &exist_part);
            }
        } else {
            return Err(NFSCRSInnerError::InvalidArgument(format!(
                "wrong path: {}",
                path.display()
            ))
            .into());
            // TODO: even root are not exists, how to handle such case
        }
        if !parents {
            return Err(NFSCRSInnerError::InvalidArgument(format!(
                "path {} not exists",
                path.parent()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default()
            ))
            .into());
        }

        self.create_dir_inner(path, &exist_part)
    }
    fn create_dir_inner(
        &mut self,
        target_dir: &AbsolutePath,
        exist_part: &AbsolutePath,
    ) -> Result<(), NFSCRSError> {
        println!("exist_part: {}", exist_part.display());
        // assume exists_part is a subpath or target dir
        let stripped_path = target_dir.strip_prefix(exist_part).map_err(|e| {
            NFSCRSInnerError::InvalidArgument(format!("failed to strip_prefix: {:?}", e))
        })?;
        let mut cops = NFS4CompoundProcedure::new();
        push_lookup_ops(&mut cops, exist_part)?;
        for c in stripped_path.components() {
            match c {
                Component::RootDir => {
                    // do nothing
                }
                Component::CurDir => {
                    // do nothing
                }
                Component::ParentDir => {
                    //TODO: look up parent dir
                }
                Component::Normal(name) => {
                    let create_arg = NFSArgOp4::OP_CREATE(Create4Args {
                        obj_type: CreateType4::NF4DIR,
                        obj_name: ByteBuf::from(name.as_bytes()),
                        create_attrs: FAttr4::simple_dir_attr(),
                    });
                    cops.add_operation(create_arg);
                }
                Component::Prefix(p) => {
                    return Err(NFSCRSInnerError::InvalidArgument(format!(
                        "Prefix component not supported: {:?}",
                        p
                    ))
                    .into());
                }
            }
        }
        let result = self.send_cops_and_get_result(&cops)?;
        if result.is_status_ok() {
            Ok(())
        } else {
            println!("failed to create directory");
            Err(NFSCRSError::NFSStatError(result.status))
        }
    }
}

fn push_lookup_and_getattr_ops(
    cops: &mut NFS4CompoundProcedure,
    path: &AbsolutePath,
    attr: GetAttr4Args,
) -> Result<(), NFSCRSInnerError> {
    cops.add_operation(NFSArgOp4::OP_PUTROOTFH);
    cops.add_operation(NFSArgOp4::OP_GETATTR(attr.clone()));
    for c in path.components() {
        match c {
            Component::RootDir => {
                // do nothing here, since we already pushed the root file handle
            }
            Component::Normal(_) => {
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
            Component::CurDir => {
                // do nothing here
            }
            Component::ParentDir => {
                // TODO: Implement parent directory lookup
                unimplemented!()
            }
            Component::Prefix(p) => {
                return Err(NFSCRSInnerError::InvalidArgument(format!(
                    "Prefix component not supported: {:?}",
                    p
                )));
            }
        }
        cops.add_operation(NFSArgOp4::OP_GETATTR(attr.clone()));
    }
    Ok(())
}

fn push_lookup_ops(
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

fn construct_path_with_n_components(
    prev_path: &AbsolutePath,
    n: usize,
) -> Result<AbsolutePath<'static>, NFSCRSInnerError> {
    let mut new_path = PathBuf::new();
    for c in prev_path.components().take(n) {
        new_path.push(c);
    }
    Ok(AbsolutePath::try_from(new_path)?)
}

mod misc {
    use crate::{
        NFSCRSInnerError,
        fattr4_utils::is_dir,
        nfsv4_ops::{GetAttr4Result, NFSResultOp4},
    };

    pub(crate) fn check_op_getattr_and_is_dir(op: &NFSResultOp4) -> Result<bool, NFSCRSInnerError> {
        match op {
            NFSResultOp4::OP_GETATTR(GetAttr4Result::NFS4_OK(attr)) => {
                Ok(is_dir(&attr.obj_attributes)?)
            }
            _ => {
                return Err(NFSCRSInnerError::InvalidArgument(format!(
                    "operation is not OP_GETATTR: {op:?}"
                )));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_construct_path_with_n_components() {
        let path = AbsolutePath::try_from("/a/b/c").unwrap();
        let new_path = construct_path_with_n_components(&path, 3).unwrap();
        assert_eq!(new_path, AbsolutePath::try_from("/a/b").unwrap());
    }
}
