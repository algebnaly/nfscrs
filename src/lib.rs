#![allow(non_camel_case_types)]
#![allow(dead_code)]
use std::{
    cell::Cell,
    fmt::Formatter,
    io::Write,
    net::{SocketAddr, TcpStream},
    os::unix::ffi::OsStrExt,
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
    thread::sleep,
    time::Duration,
};

use crate::{
    auth::AuthType,
    constants::{READDIR_DEFAULT_ATTR, READDIR_MAX_COUNT},
    fattr4::{FAttr4, FAttr4Type, fattr4_names},
    fattr4_utils::bit_nums_to_attr_mask,
    nfs4_types::{BitMap4, ClientId4, Count4, NFSFH4, Offset4},
    nfscrs_error::{NFSCRSError, NFSCRSInnerError},
    nfscrs_types::{AbsolutePath, DirEntry},
    nfsv4_ops::{
        CallBackClient4, ChangeInfo4, Close4Args, Close4Result, Compound4Result, Create4Args,
        CreateType4, GetAttr4Args, GetAttr4Result, GetFH4Result, LookUp4Args,
        NFS4CompoundProcedure, NFSArgOp4, NFSClientId4, NFSResultOp4, NFSStat4, Open4Args,
        Open4Result, OpenConfirm4Args, OpenConfirm4Result, PutFH4Args, Read4Args, Read4Result,
        ReadDir4Args, ReadDir4Result, Remove4Args, Remove4Result, Renew4Args, SetAttr4Args,
        SetClientId4Args, SetClientId4Result, SetClientIdConfirm4Args, StateId4, Verifier4,
        Write4Args, Write4Result,
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
pub mod nfs4_open;
pub mod nfs4_open_owner;
pub mod nfs4_types;
pub mod nfs4_utils;
pub mod nfscrs_error;
pub mod nfscrs_types;
mod nfsv4_ops;
mod nfsv4_rpc_def;
mod oncrpc_msg;
mod simple_api;
mod state;
mod xdr_types;

pub use state::*;

#[derive(Debug)]
pub struct NFSClientBuilder {
    xid: Cell<u32>,
    auth: AuthType,
    msg_reader: ONCRPCMessageReader,
    remote_addr: SocketAddr,
}

#[derive(Debug)]
pub struct ServerInfo {
    pub lease_time: usize, // in secs
}

#[derive(Debug)]
pub struct NFSClientSession {
    nfs_transport: Arc<Mutex<NFSTransport>>,
    remote_addr: SocketAddr,
    client_id: ClientId4,
    server_info: ServerInfo, // TODO: add a handler to backgroud renew thread
    open_owner: Arc<crate::nfs4_open_owner::OpenOwner>,
}

pub struct NFSTransport {
    xid: Cell<u32>,
    auth: AuthType,
    stream: TcpStream,
    msg_reader: ONCRPCMessageReader,
}

impl std::fmt::Debug for NFSTransport {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NFSTransport")
            .field("xid", &self.xid.get())
            .field("auth", &self.auth)
            .finish()
    }
}

impl NFSTransport {
    fn new(xid: u32, auth: AuthType, stream: TcpStream, msg_reader: ONCRPCMessageReader) -> Self {
        let xid = Cell::new(xid);
        Self {
            xid,
            auth,
            stream,
            msg_reader,
        }
    }

    fn pop_xid(&self) -> u32 {
        let current_xid = self.xid.get();
        self.xid.set(current_xid.wrapping_add(1));
        current_xid
    }
    fn send_msg<P: AsRef<[u8]>>(
        &mut self,
        msg: onc_rpc::RpcMessage<String, P>,
    ) -> Result<(), NFSCRSError> {
        let buf = msg.serialise().unwrap();
        self.stream.write(&buf).map_err(|e| {
            NFSCRSError::SendMessage(format!("failed to write to TcpStream: {e:?}"))
        })?;
        Ok(())
    }
    fn read_reply(&mut self) -> Result<RpcMessage<onc_rpc::Bytes, onc_rpc::Bytes>, NFSCRSError> {
        let reply = self.msg_reader.read(&mut self.stream)?;
        Ok(reply)
    }

    fn read_cops_result(&mut self) -> Result<Compound4Result, NFSCRSError> {
        let reply = self.read_reply()?;
        read_compound_result(&reply).map_err(|e| e.into())
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

    fn send_ops_and_get_result(
        &mut self,
        cops: &NFS4CompoundProcedure,
    ) -> Result<Compound4Result, NFSCRSError> {
        let payload = cops.to_bytes()?;
        let msg = self.get_onc_rpc_compound_call_message(payload);
        self.send_msg(msg)?;
        self.read_cops_result()
    }
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
        cops.add_operation(NFSArgOp4::OP_PUTROOTFH);
        cops.add_operation(NFSArgOp4::OP_GETATTR(GetAttr4Args {
            attr_request: bit_nums_to_attr_mask(&[fattr4_names::FATTR4_LEASE_TIME]),
        }));

        let payload = cops.to_bytes()?;
        let cops_msg = self.get_onc_rpc_compound_call_message(payload);
        self.send_msg(cops_msg, &mut stream)?;
        let reply = self.read_reply(&mut stream)?;
        let mut result = read_compound_result(&reply)?;
        if !result.is_status_ok() {
            return Err(NFSCRSError::NFSStatError(result.status));
        }

        let Some(NFSResultOp4::OP_GETATTR(GetAttr4Result::NFS4_OK(get_attr_result_ok))) =
            result.resarray.pop()
        else {
            return Err(NFSCRSError::EmptyReplyBody);
        };
        let lease_time = match get_attr_result_ok
            .obj_attributes
            .fetch_attr(fattr4_names::FATTR4_LEASE_TIME)?
        {
            FAttr4Type::FATTR4_LEASE_TIME(t) => t,
            _ => return Err(NFSCRSError::EmptyReplyBody),
        };

        result.resarray.pop(); // discard PUTROOTFH result

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

        let xid = Cell::new(self.pop_xid());
        let nfs_transport = Arc::new(Mutex::new(NFSTransport::new(
            xid.get(),
            self.auth,
            stream,
            self.msg_reader,
        )));
        let nfs_transport_ref = nfs_transport.clone();

        std::thread::spawn(move || {
            loop {
                sleep(Duration::from_secs((lease_time / 2) as u64));
                {
                    let mut nfs_transport_guard = nfs_transport_ref
                        .lock()
                        .expect("failed to aquire nfs transport");
                    renew_operation(client_id, &mut *nfs_transport_guard).expect("failed to renew");
                }
            }
        });

        let session = NFSClientSession {
            nfs_transport: nfs_transport,
            remote_addr: self.remote_addr,
            client_id,
            server_info: ServerInfo {
                lease_time: lease_time as usize,
            },
            open_owner: Arc::new(crate::nfs4_open_owner::OpenOwner::new(ByteBuf::from(
                b"simple_open",
            ))),
        };

        Ok(session)
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
    pub(crate) fn send_ops_and_get_result_wrapper(
        &self,
        cops: &NFS4CompoundProcedure,
    ) -> Result<Compound4Result, NFSCRSError> {
        let mut transport_guard = self.nfs_transport.lock().map_err(|e| {
            NFSCRSInnerError::PoisonedMutex(format!("failed to lock stream: {:?}", e))
        })?;

        transport_guard.send_ops_and_get_result(cops)
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
        let result = {
            let mut transport_guard = self.nfs_transport.lock().map_err(|e| {
                NFSCRSInnerError::PoisonedMutex(format!("failed to lock stream: {:?}", e))
            })?;

            let result = transport_guard.send_ops_and_get_result(&cops)?;
            result
        };

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

        let result = {
            let mut transport_guard = self.nfs_transport.lock().map_err(|e| {
                NFSCRSInnerError::PoisonedMutex(format!("failed to lock stream: {:?}", e))
            })?;

            let result = transport_guard.send_ops_and_get_result(&cops)?;
            result
        };

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

            let mut result = self.send_ops_and_get_result_wrapper(&cops)?;

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

    pub(crate) fn open(
        &mut self,
        path: &AbsolutePath,
        open_options: OpenOptions,
        seq_id: &mut u32,
    ) -> Result<OpenedFile, NFSCRSError> {
        let mut cops = NFS4CompoundProcedure::new();

        let (dirs, filename) = split_path(path)?;

        push_lookup_ops(&mut cops, &dirs)?;

        let open_owner_ref = self.open_owner.clone();
        let path_clone = path.clone().into_owned();

        tracing::debug!("open: path = {}, seq_id = {:?}", path, seq_id);

        if let Some(file_key_inner) = open_owner_ref.path_map.get(&path_clone)
            && let Some(file_open_state) = open_owner_ref.files.get(&file_key_inner)
        {
            let share_access = open_options.get_share_access();

            file_open_state.ref_count_inc();
            return Ok(file_open_state.get_opened_file(share_access, 0, path_clone));
        }

        let seq_id_val = *seq_id;
        *seq_id += 1;

        let open_args = Open4Args::with_open_options(self, filename, seq_id_val, open_options);

        let share_access = open_args.share_access;
        let share_deny = open_args.share_deny;

        cops.add_operation(NFSArgOp4::OP_OPEN(open_args));
        cops.add_operation(NFSArgOp4::OP_GETATTR(GetAttr4Args {
            attr_request: bit_nums_to_attr_mask(&[
                fattr4_names::FATTR4_FSID,
                fattr4_names::FATTR4_FILEID,
            ]),
        }));
        cops.add_operation(NFSArgOp4::OP_GETFH);
        let result = self.send_ops_and_get_result_wrapper(&cops)?;
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

        let get_attr_result = res_array.pop().unwrap();
        let NFSResultOp4::OP_GETATTR(GetAttr4Result::NFS4_OK(get_attr_result_ok)) = get_attr_result
        else {
            return Err(
                NFSCRSInnerError::WrongMessageType("expecting GetAttr4Result".to_owned()).into(),
            );
        };

        let fsid = match get_attr_result_ok
            .obj_attributes
            .fetch_attr(fattr4_names::FATTR4_FSID)?
        {
            FAttr4Type::FATTR4_FSID(fsid) => fsid,
            other => {
                return Err(NFSCRSInnerError::WrongOperationReply(format!(
                    "expecting fsid but get {:?}",
                    other,
                ))
                .into());
            }
        };

        let file_id = match get_attr_result_ok
            .obj_attributes
            .fetch_attr(fattr4_names::FATTR4_FILEID)?
        {
            FAttr4Type::FATTR4_FILEID(file_id) => file_id,
            other => {
                return Err(NFSCRSInnerError::WrongOperationReply(format!(
                    "expecting file_id but get {:?}",
                    other,
                ))
                .into());
            }
        };

        let open_result = res_array.pop().unwrap();
        let NFSResultOp4::OP_OPEN(Open4Result::NFS4_OK(open_result_ok)) = open_result else {
            return Err(
                NFSCRSInnerError::WrongMessageType("expecting Open4Result".to_owned()).into(),
            );
        };

        let file_key = FileKey { fsid, file_id };

        let state_id = open_result_ok.state_id.clone();

        let opening_file = OpenedFileBuilder {
            file_key,
            get_fh_result: get_fh_result_ok.clone(),
            open_result: open_result_ok.clone(),
            requested_share_access: share_access,
            requested_share_deny: share_deny,
            path: path.clone().into_owned(),
        }
        .build()?;

        open_owner_ref.files.insert(
            file_key,
            OpenFileState::new(
                get_fh_result_ok.object,
                file_key,
                state_id,
                share_access,
                share_deny,
                open_result_ok.rflags,
            ),
        );
        open_owner_ref.path_map.insert(path_clone, file_key);
        Ok(opening_file)
    }

    pub(crate) fn open_confirm(
        &mut self,
        opened_file: OpenedFile,
        seq_id: &mut u32,
    ) -> Result<OpenedFile, NFSCRSError> {
        let mut cops = NFS4CompoundProcedure::new();
        cops.add_operation(NFSArgOp4::OP_PUTFH(PutFH4Args {
            object: opened_file.file_handle.clone(),
        }));
        let open_owner_ref = self.open_owner.clone();

        tracing::debug!(
            "open_confirm: path = {}, seq_id = {:?}",
            opened_file.path,
            seq_id
        );
        let seq_id_val = *seq_id;
        *seq_id += 1;

        let mut file_open_state = open_owner_ref.files.get_mut(&opened_file.file_key).ok_or(
            NFSCRSInnerError::InvalidArgument("open_confirm with no file open".to_string()),
        )?;

        let state_id = file_open_state.get_state_id()?;

        let open_confirm_args = OpenConfirm4Args {
            open_stateid: state_id,
            seq_id: seq_id_val,
        };

        cops.add_operation(NFSArgOp4::OP_OPEN_CONFIRM(open_confirm_args));
        let result = self.send_ops_and_get_result_wrapper(&cops)?;
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

        file_open_state.update_state_id(open_confirm_result_ok.open_stateid)?;
        file_open_state.set_confirmed();
        Ok(opened_file)
    }

    pub fn close(&mut self, opened_file: &mut OpenedFile) -> Result<(), NFSCRSError> {
        let open_owner_ref = self.open_owner.clone();
        let mut seq_id_and_path_guard = open_owner_ref.lock_seq_id_and_path(&opened_file.path)?;
        let seq_id = &mut *seq_id_and_path_guard.seq_id_guard;

        tracing::debug!("close: path = {}, seq_id = {:?}", opened_file.path, seq_id);

        let state_id: StateId4;
        let needs_close: bool;
        {
            let mut file_open_state_entry = match open_owner_ref.files.entry(opened_file.file_key) {
                dashmap::Entry::Occupied(v) => v,
                dashmap::Entry::Vacant(_) => {
                    return Err(NFSCRSInnerError::InvalidArgument(
                        "cannot close a file that not open".to_string(),
                    )
                    .into());
                }
            };

            let pre_ref_count = file_open_state_entry.get_mut().ref_count_dec();
            if pre_ref_count <= 0 {
                return Err(NFSCRSInnerError::InvalidArgument(
                    "ref count smaller than 0".to_string(),
                )
                .into());
            }

            if pre_ref_count > 1 {
                return Ok(());
            }
            state_id = file_open_state_entry.get().get_state_id()?;
            needs_close = true;
        } // release file_open_state_entry

        if needs_close {
            let seq_id_val = *seq_id;
            *seq_id += 1;

            let mut cops = NFS4CompoundProcedure::new();
            cops.add_operation(NFSArgOp4::OP_PUTFH(PutFH4Args {
                object: opened_file.file_handle.clone(),
            }));
            cops.add_operation(NFSArgOp4::OP_CLOSE(Close4Args {
                seq_id: seq_id_val,
                open_state_id: state_id,
            }));

            let result = match self.send_ops_and_get_result_wrapper(&cops) {
                Ok(res) => res,
                Err(e) => {
                    if let Some(entry) = open_owner_ref.files.get_mut(&opened_file.file_key) {
                        entry.ref_count_inc();
                    }
                    return Err(e);
                }
            };

            if !result.is_status_ok() {
                return Err(NFSCRSError::NFSStatError(result.status));
            }
            let mut res_array = result.resarray;
            let close_result = res_array.pop().unwrap();
            let NFSResultOp4::OP_CLOSE(Close4Result::NFS4_OK(_close_result_seq_id)) = close_result
            else {
                return Err(NFSCRSInnerError::WrongMessageType(
                    "expecting Close4Result".to_owned(),
                )
                .into());
            };
        }

        open_owner_ref.files.remove(&opened_file.file_key);
        open_owner_ref
            .path_map
            .remove(&opened_file.path)
            .ok_or(NFSCRSInnerError::IllegalState(
                "failed to remove opened file state".to_string(),
            ))?;

        Ok(())
    }

    pub fn read(
        &mut self,
        opened_file: &mut OpenedFile,
        count: usize,
    ) -> Result<ReadResult, NFSCRSError> {
        let open_owner_ref = self.open_owner.clone();
        let file_open_state = open_owner_ref.files.get(&opened_file.file_key).ok_or(
            NFSCRSInnerError::InvalidArgument("cannot close a file that not open".to_string()),
        )?;

        let state_id = file_open_state.get_state_id()?;

        let mut cops = NFS4CompoundProcedure::new();
        cops.add_operation(NFSArgOp4::OP_PUTFH(PutFH4Args {
            object: opened_file.file_handle.clone(),
        }));
        cops.add_operation(NFSArgOp4::OP_READ(Read4Args {
            state_id: state_id,
            offset: opened_file.offset as Offset4,
            count: count as Count4,
        }));

        let result = self.send_ops_and_get_result_wrapper(&cops)?;

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
        let open_owner_ref = self.open_owner.clone();
        let file_open_state = open_owner_ref.files.get(&opened_file.file_key).ok_or(
            NFSCRSInnerError::InvalidArgument("cannot close a file that not open".to_string()),
        )?;

        let state_id = file_open_state.get_state_id()?;

        let mut cops = NFS4CompoundProcedure::new();
        cops.add_operation(NFSArgOp4::OP_PUTFH(PutFH4Args {
            object: opened_file.file_handle.clone(),
        }));

        cops.add_operation(NFSArgOp4::OP_WRITE(Write4Args {
            state_id: state_id,
            offset: opened_file.offset as u64,
            stable: nfsv4_ops::StableHow4::UNSTABLE4,
            data: Opaque::from(data),
        }));
        let result = self.send_ops_and_get_result_wrapper(&cops)?;
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
        let mut opened_file = self.open_file(path, OpenOptions::new().write(true))?;

        let open_owner_ref = self.open_owner.clone();
        let file_open_state = open_owner_ref.files.get(&opened_file.file_key).ok_or(
            NFSCRSInnerError::IllegalState("file should opened".to_string()),
        )?;

        let state_id = file_open_state.get_state_id()?;

        let bitmap = self.set_attr(&opened_file.file_handle, &fattr4, &state_id)?;

        self.close(&mut opened_file)?;
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
        let mut result = self.send_ops_and_get_result_wrapper(&cops)?;
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
        let mut result = self.send_ops_and_get_result_wrapper(&cops)?;
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

        let result = self.send_ops_and_get_result_wrapper(&cops)?;
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

    pub fn open_file_need_confirm(&self, opened_file: &OpenedFile) -> Result<bool, NFSCRSError> {
        let file_key = opened_file.file_key;
        let open_owner_ref = self.open_owner.clone();
        let open_file_state =
            open_owner_ref
                .files
                .get(&file_key)
                .ok_or(NFSCRSInnerError::IllegalState(
                    "opened file not found".to_string(),
                ))?;
        Ok(open_file_state.need_confirm())
    }

    fn create_dir_inner(
        &mut self,
        target_dir: &AbsolutePath,
        exist_part: &AbsolutePath,
    ) -> Result<(), NFSCRSError> {
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
                        create_attrs: FAttr4::simple_dir_attr(), // TODO: setup dir attr
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

        let result = self.send_ops_and_get_result_wrapper(&cops)?;

        if result.is_status_ok() {
            Ok(())
        } else {
            Err(NFSCRSError::NFSStatError(result.status))
        }
    }

    pub fn remove(&mut self, path: &AbsolutePath) -> Result<ChangeInfo4, NFSCRSError> {
        let name = path.file_name().ok_or(NFSCRSInnerError::InvalidArgument(
            "cannot remove file system root".to_string(),
        ))?;

        let parent = path
            .parent_absolute()
            .ok_or(NFSCRSInnerError::InvalidArgument(
                "cannot remove file system root".to_string(),
            ))?;

        let mut cops = NFS4CompoundProcedure::new();
        push_lookup_ops(&mut cops, &parent)?;
        cops.add_operation(NFSArgOp4::OP_REMOVE(Remove4Args {
            target: ByteBuf::from(name.as_bytes()),
        }));
        let mut result = self.send_ops_and_get_result_wrapper(&cops)?;
        if !result.is_status_ok() {
            return Err(NFSCRSError::NFSStatError(result.status));
        };
        let cinfo = if let Some(NFSResultOp4::OP_REMOVE(remove_result)) = result.resarray.pop()
            && let Remove4Result::NFS4_OK(remove_result_ok) = remove_result
        {
            remove_result_ok.cinfo
        } else {
            return Err(
                NFSCRSInnerError::WrongOperationReply("expecting OP_REMOVE".to_string()).into(),
            );
        };
        Ok(cinfo)
    }
}

fn renew_operation(client_id: u64, nfs_transport: &mut NFSTransport) -> Result<(), NFSCRSError> {
    let mut cops = NFS4CompoundProcedure::new();
    cops.add_operation(NFSArgOp4::OP_RENEW(Renew4Args { client_id }));
    let r = nfs_transport.send_ops_and_get_result(&cops)?;
    if r.is_status_ok() {
        Ok(())
    } else {
        Err(NFSCRSError::NFSStatError(r.status))
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
