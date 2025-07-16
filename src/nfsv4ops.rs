use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::{
    NFSCRSError, NFSCRSInnerError, NFSClientSession,
    nfs4types::{
        AttrList4, BitMap4, ClientId4, Component4, Count4, NFS4_OPAQUE_LIMIT, NFS4_OTHER_SIZE,
        NFSCookie4, SeqId4,
    },
    nfscrs_types::DirEntry,
    xdr_types::Opaque,
};

pub const TAG: &str = "nfscrstag";

#[derive(Debug, Serialize)]
pub enum NFSArgOp4 {
    _PlaceHolder0,
    _PlaceHolder1,
    _PlaceHolder2,
    OP_ACCESS,                                       //ACCESS4args opaccess;
    OP_CLOSE,                                        //CLOSE4args opclose;
    OP_COMMIT,                                       //COMMIT4args opcommit;
    OP_CREATE,                                       //CREATE4args opcreate;
    OP_DELEGPURGE,                                   //DELEGPURGE4args opdelegpurge;
    OP_DELEGRETURN,                                  //DELEGRETURN4args opdelegreturn;
    OP_GETATTR(GetAttr4Args),                        //GETATTR4args opgetattr;
    OP_GETFH,                                        //void;
    OP_LINK,                                         //LINK4args oplink;
    OP_LOCK,                                         //LOCK4args oplock;
    OP_LOCKT,                                        //LOCKT4args oplockt;
    OP_LOCKU,                                        //LOCKU4args oplocku;
    OP_LOOKUP(LookUp4Args),                          //LOOKUP4args oplookup;
    OP_LOOKUPP,                                      //void;
    OP_NVERIFY,                                      //NVERIFY4args opnverify;
    OP_OPEN(Open4Args),                              //OPEN4args opopen;
    OP_OPENATTR,                                     //OPENATTR4args opopenattr;
    OP_OPEN_CONFIRM,                                 //OPEN_CONFIRM4args opopen_confirm;
    OP_OPEN_DOWNGRADE,                               //OPEN_DOWNGRADE4args opopen_downgrade;
    OP_PUTFH,                                        //PUTFH4args opputfh;
    OP_PUTPUBFH,                                     //void;
    OP_PUTROOTFH,                                    //void;
    OP_READ,                                         //READ4args opread;
    OP_READDIR(ReadDir4Args),                        //READDIR4args opreaddir;
    OP_READLINK,                                     //void;
    OP_REMOVE,                                       //REMOVE4args opremove;
    OP_RENAME,                                       //RENAME4args oprename;
    OP_RENEW,                                        //RENEW4args oprenew;
    OP_RESTOREFH,                                    //void;
    OP_SAVEFH,                                       //void;
    OP_SECINFO,                                      //SECINFO4args opsecinfo;
    OP_SETATTR,                                      //SETATTR4args opsetattr;
    OP_SETCLIENTID(SetClientId4Args),                //SETCLIENTID4args opsetclientid;
    OP_SETCLIENTID_CONFIRM(SetClientIdConfirm4Args), //SETCLIENTID_CONFIRM4args opsetclientid_confirm;
    OP_VERIFY,                                       //VERIFY4args opverify;
    OP_WRITE,                                        //WRITE4args opwrite;
    OP_RELEASE_LOCKOWNER,                            //RELEASE_LOCKOWNER4args oprelease_lockowner;
    OP_ILLEGAL,                                      //void;// well, this is actually 10044
}

#[derive(Debug, Deserialize)]
pub enum NFSResponseOperation4 {
    _PlaceHolder0,
    _PlaceHolder1,
    _PlaceHolder2,
    OP_ACCESS,
    OP_CLOSE,
    OP_COMMIT,
    OP_CREATE,
    OP_DELEGPURGE,
    OP_DELEGRETURN,
    OP_GETATTR(GetAttr4Res),
    OP_GETFH,
    OP_LINK,
    OP_LOCK,
    OP_LOCKT,
    OP_LOCKU,
    OP_LOOKUP(LookUp4Res),
    OP_LOOKUPP,
    OP_NVERIFY,
    OP_OPEN,
    OP_OPENATTR,
    OP_OPEN_CONFIRM,
    OP_OPEN_DOWNGRADE,
    OP_PUTFH,
    OP_PUTPUBFH,
    OP_PUTROOTFH(PutRootFH4Res),
    OP_READ,
    OP_READDIR(ReadDir4Result),
    OP_READLINK,
    OP_REMOVE,
    OP_RENAME,
    OP_RENEW,
    OP_RESTOREFH,
    OP_SAVEFH,
    OP_SECINFO,
    OP_SETATTR,
    OP_SETCLIENTID(SetClientId4Result),
    OP_SETCLIENTID_CONFIRM(SetClientIdConfirm4Result),
    OP_VERIFY,
    OP_WRITE,
    OP_RELEASE_LOCKOWNER,
    OP_ILLEGAL,
}

#[derive(Debug, Deserialize, Clone)]
pub enum NFSStat4 {
    NFS4_OK,                     /*                0 everything is okay       */
    NFS4ERR_PERM,                /*           1 caller not privileged    */
    NFS4ERR_NOENT,               /*          2 no such file/directory   */
    NFS4ERR_IO,                  /*             5 hard I/O error           */
    NFS4ERR_NXIO,                /*           6 no such device           */
    NFS4ERR_ACCESS,              /*         13 access denied            */
    NFS4ERR_EXIST,               /*          17 file already exists      */
    NFS4ERR_XDEV,                /*           18 different file systems   */
    _NFSSTAT4_UNUSED,            /*19  Unused/reserved        */
    NFS4ERR_NOTDIR,              /*         20 should be a directory    */
    NFS4ERR_ISDIR,               /*          21 should not be directory  */
    NFS4ERR_INVAL,               /*          22 invalid argument         */
    NFS4ERR_FBIG,                /*           27 file exceeds server max  */
    NFS4ERR_NOSPC,               /*          28 no space on file system  */
    NFS4ERR_ROFS,                /*           30 read-only file system    */
    NFS4ERR_MLINK,               /*          31 too many hard links      */
    NFS4ERR_NAMETOOLONG,         /*    63 name exceeds server max  */
    NFS4ERR_NOTEMPTY,            /*       66 directory not empty      */
    NFS4ERR_DQUOT,               /*          69 hard quota limit reached */
    NFS4ERR_STALE,               /*          70 file no longer exists    */
    NFS4ERR_BADHANDLE,           /*      10001 Illegal filehandle       */
    NFS4ERR_BAD_COOKIE,          /*     10003 READDIR cookie is stale  */
    NFS4ERR_NOTSUPP,             /*        10004 operation not supported  */
    NFS4ERR_TOOSMALL,            /*       10005 response limit exceeded  */
    NFS4ERR_SERVERFAULT,         /*    10006 undefined server error   */
    NFS4ERR_BADTYPE,             /*        10007 type invalid for CREATE  */
    NFS4ERR_DELAY,               /*          10008 file "busy" - retry      */
    NFS4ERR_SAME,                /*           10009 nverify says attrs same  */
    NFS4ERR_DENIED,              /*         10010 lock unavailable         */
    NFS4ERR_EXPIRED,             /*        10011 lock lease expired       */
    NFS4ERR_LOCKED,              /*         10012 I/O failed due to lock   */
    NFS4ERR_GRACE,               /*          10013 in grace period          */
    NFS4ERR_FHEXPIRED,           /*      10014 filehandle expired       */
    NFS4ERR_SHARE_DENIED,        /*   10015 share reserve denied     */
    NFS4ERR_WRONGSEC,            /*       10016 wrong security flavor    */
    NFS4ERR_CLID_INUSE,          /*     10017 clientid in use          */
    NFS4ERR_RESOURCE,            /*       10018 resource exhaustion      */
    NFS4ERR_MOVED,               /*          10019 file system relocated    */
    NFS4ERR_NOFILEHANDLE,        /*   10020 current FH is not set    */
    NFS4ERR_MINOR_VERS_MISMATCH, /* 10021 minor vers not supp */
    NFS4ERR_STALE_CLIENTID,      /* 10022 server has rebooted      */
    NFS4ERR_STALE_STATEID,       /*  10023 server has rebooted      */
    NFS4ERR_OLD_STATEID,         /*    10024 state is out of sync     */
    NFS4ERR_BAD_STATEID,         /*    10025 incorrect stateid        */
    NFS4ERR_BAD_SEQID,           /*      10026 request is out of seq.   */
    NFS4ERR_NOT_SAME,            /*       10027 verify - attrs not same  */
    NFS4ERR_LOCK_RANGE,          /*     10028 lock range not supported */
    NFS4ERR_SYMLINK,             /*        10029 should be file/directory */
    NFS4ERR_RESTOREFH,           /*      10030 no saved filehandle      */
    NFS4ERR_LEASE_MOVED,         /*    10031 some file system moved   */
    NFS4ERR_ATTRNOTSUPP,         /*    10032 recommended attr not sup */
    NFS4ERR_NO_GRACE,            /*       10033 reclaim outside of grace */
    NFS4ERR_RECLAIM_BAD,         /*    10034 reclaim error at server  */
    NFS4ERR_RECLAIM_CONFLICT,    /* 10035 conflict on reclaim    */
    NFS4ERR_BADXDR,              /*         10036 XDR decode failed        */
    NFS4ERR_LOCKS_HELD,          /*     10037 file locks held at CLOSE */
    NFS4ERR_OPENMODE,            /*       10038 conflict in OPEN and I/O */
    NFS4ERR_BADOWNER,            /*       10039 owner translation bad    */
    NFS4ERR_BADCHAR,             /*        10040 UTF-8 char not supported */
    NFS4ERR_BADNAME,             /*        10041 name not supported       */
    NFS4ERR_BAD_RANGE,           /*      10042 lock range not supported */
    NFS4ERR_LOCK_NOTSUPP,        /*   10043 no atomic up/downgrade   */
    NFS4ERR_OP_ILLEGAL,          /*     10044 undefined operation      */
    NFS4ERR_DEADLOCK,            /*       10045 file locking deadlock    */
    NFS4ERR_FILE_OPEN,           /*      10046 open file blocks op.     */
    NFS4ERR_ADMIN_REVOKED,       /*  10047 lock-owner state revoked */
    NFS4ERR_CB_PATH_DOWN,        /*10048  callback path down       */
}

#[derive(Debug, Deserialize)]
pub struct Compound4Result {
    pub status: NFSStat4,
    pub tag: String,
    pub resarray: Vec<NFSResponseOperation4>,
}

impl Compound4Result {
    pub fn is_status_ok(&self) -> bool {
        matches!(self.status, NFSStat4::NFS4_OK)
    }
}

#[derive(Debug, Serialize)]
pub struct GetAttr4Args {
    /* CURRENT_FH: directory or file */
    attr_request: BitMap4,
}

impl GetAttr4Args {
    pub fn new(attr_request: BitMap4) -> Self {
        Self { attr_request }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct GetAttr4ResOk {
    pub obj_attributes: FAttr4,
}

#[derive(Debug, Deserialize)]
pub enum GetAttr4Res {
    NFS4_OK(GetAttr4ResOk),
    Default,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PutRootFH4Res {
    status: NFSStat4,
}

pub const NFS4_VERIFIER_SIZE: usize = 8;

#[derive(Debug, Serialize, Deserialize, PartialEq, Default, Clone)]
pub struct Verifier4 {
    #[serde(with = "serde_xdr::opaque_data::fixed_length")]
    pub verifier4: [u8; NFS4_VERIFIER_SIZE],
}

impl Verifier4 {
    pub const fn zero() -> Self {
        Self {
            verifier4: [0; NFS4_VERIFIER_SIZE],
        }
    }
}

#[derive(Debug, Deserialize)]
pub enum SetClientId4Result {
    NFS4_OK(SetClientIdResultOK),
    NFS4ERR_CLID_INUSE(ClientAddr4), //this has to be fix!
    DefaultArm,
}

#[derive(Debug, Serialize)]
pub struct NFSClientId4 {
    verifier: Verifier4,

    id: ByteBuf, // maximum length is NFS4_OPAQUE_LIMIT,1024.
}

impl NFSClientId4 {
    pub fn new(verifier: Verifier4, id: Vec<u8>) -> Self {
        Self {
            verifier,
            id: serde_bytes::ByteBuf::from(id),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SetClientId4Args {
    client: NFSClientId4,
    callback: CallBackClient4,
    callback_ident: u32,
}

impl SetClientId4Args {
    pub fn build(
        client: NFSClientId4,
        callback: CallBackClient4,
        callback_ident: u32,
    ) -> Result<SetClientId4Args, NFSCRSInnerError> {
        if client.id.len() > NFS4_OPAQUE_LIMIT {
            return Err(NFSCRSInnerError::InvalidArgument(
                "client.id length greater then NFS4_OPAQUE_LIMIT".to_owned(),
            ));
        }
        Ok(Self {
            client,
            callback,
            callback_ident,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct CallBackClient4 {
    cb_program: u32,
    cb_location: ClientAddr4,
}

impl CallBackClient4 {
    pub fn dummy_callback() -> Self {
        // since we are not ready to implement callback.
        Self {
            cb_program: 0,
            cb_location: ClientAddr4::loopback_port_0(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ClientAddr4 {
    /* see struct rpcb in RFC 1833 */
    r_netid: String, /* network id */
    r_addr: String,  /* universal address */
}

impl ClientAddr4 {
    pub fn loopback_port_0() -> Self {
        Self {
            r_netid: "tcp".to_owned(),
            r_addr: "127.0.0.1.0.0".to_owned(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct SetClientIdResultOK {
    pub client_id: ClientId4,
    pub set_client_id_confirm: Verifier4,
}

#[derive(Debug, Serialize)]
pub struct NFS4CompoundProcedure {
    tag: String,
    minorversion: u32,
    argarray: Vec<NFSArgOp4>,
}

impl NFS4CompoundProcedure {
    pub fn new() -> Self {
        Self {
            tag: TAG.to_owned(),
            minorversion: 0,
            argarray: Vec::new(),
        }
    }

    // append a operation to the end of this compound procedural
    pub fn add_operation(&mut self, op: NFSArgOp4) {
        self.argarray.push(op);
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>, NFSCRSInnerError> {
        serde_xdr::to_bytes(&self).map_err(NFSCRSInnerError::from)
    }
}

#[derive(Debug, Serialize)]
pub struct SetClientIdConfirm4Args {
    pub client_id: ClientId4,
    pub setclientid_confirm: Verifier4,
}

#[derive(Debug, Deserialize)]
pub struct SetClientIdConfirm4Result {
    pub status: NFSStat4,
}

#[derive(Debug, Deserialize)]
struct PutRootFH4Result {
    /* CURRENT_FH: root fh */
    status: NFSStat4,
}

#[derive(Debug, Serialize)]
pub struct ReadDir4Args {
    /* CURRENT_FH: directory */
    cookie: NFSCookie4,
    cookie_verf: Verifier4,
    dircount: Count4, // maximum number of bytes of directory information that should be returned
    maxcount: Count4, //
    attr_request: BitMap4,
}

impl ReadDir4Args {
    pub fn start_read(dircount: Count4, maxcount: Count4, attr_request: BitMap4) -> Self {
        const COOKIE_START: NFSCookie4 = 0;
        const COOKIE_VERF_START: Verifier4 = Verifier4::zero();
        Self {
            cookie: COOKIE_START,
            cookie_verf: COOKIE_VERF_START,
            dircount,
            maxcount,
            attr_request,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Entry4 {
    cookie: NFSCookie4,
    name: Component4,
    attrs: FAttr4,
    next_entry: Option<Box<Entry4>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DirList4 {
    entries: Option<Box<Entry4>>,
    eof: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ReadDir4ResultOk {
    cookie_verf: Verifier4,
    reply: DirList4,
}

impl ReadDir4ResultOk {
    pub fn readdir_complete(&self) -> bool {
        self.reply.eof
    }
    pub fn build_entries(&self) -> Vec<DirEntry> {
        let mut entries = Vec::new();
        let mut next_e = &self.reply.entries;

        while let Some(e) = next_e {
            entries.push(DirEntry::new(e.name.clone(), e.attrs.clone()));
            next_e = &e.next_entry;
        }
        entries
    }
}

#[derive(Debug, Deserialize, Clone)]
pub enum ReadDir4Result {
    NFS4_OK(ReadDir4ResultOk),
    DefautlArm,
}

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
}

#[derive(Debug, Serialize, Clone)]
pub struct LookUp4Args {
    /* CURRENT_FH: directory */
    objname: Component4,
}

impl LookUp4Args {
    pub fn new(objname: Component4) -> Self {
        Self { objname }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct LookUp4Res {
    status: NFSStat4,
}

#[derive(Debug, Serialize, Clone)]
pub struct Open4Args {
    seqid: SeqId4,
    share_access: u32,
    share_deny: u32,
    owner: OpenOwner,
    openhow: OpenFlag4,
    claim: OpenClaim4,
}

pub mod open_params {
    pub const OPEN4_SHARE_ACCESS_READ: u32 = 0x00000001;
    pub const OPEN4_SHARE_ACCESS_WRITE: u32 = 0x00000002;
    pub const OPEN4_SHARE_ACCESS_BOTH: u32 = 0x00000003;

    pub const OPEN4_SHARE_DENY_NONE: u32 = 0x00000000;
    pub const OPEN4_SHARE_DENY_READ: u32 = 0x00000001;
    pub const OPEN4_SHARE_DENY_WRITE: u32 = 0x00000002;
    pub const OPEN4_SHARE_DENY_BOTH: u32 = 0x00000003;
}

impl Open4Args {
    pub fn simple_open(session: &NFSClientSession) -> Self {
        let owner = OpenOwner {
            client_id: session.client_id,
            owner: ByteBuf::from(b"simple_open"),
        };
        Self {
            seqid: 0,
            share_access: open_params::OPEN4_SHARE_ACCESS_READ,
            share_deny: 0,
            owner,
            openhow: OpenFlag4::OPEN4_CREATE(CreateHow4::GUARDED4(FAttr4::empty_attr())),
            claim: OpenClaim4::CLAIM_NULL(ByteBuf::from("")),
        }
    }
}

#[derive(Debug, Serialize, Clone)]
struct OpenOwner {
    client_id: ClientId4,
    owner: Opaque, // with length limit of NFS4_OPAQUE_LIMIT
}

#[derive(Debug, Clone)]
#[repr(u32)]
pub enum OpenFlag4 {
    OPEN4_CREATE(CreateHow4),
    Default,
}

impl Serialize for OpenFlag4 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::OPEN4_CREATE(ch) => {
                serializer.serialize_newtype_variant("OpenFlag4", 1, "OPEN4_CREATE", ch)
            }
            Self::Default => {
                unimplemented!()
            }
        }
    }
}

#[derive(Debug, Serialize, Clone)]
pub enum CreateHow4 {
    UNCHECKED4(FAttr4),
    GUARDED4(FAttr4),
    EXCLUSIVE4(Verifier4),
}

#[derive(Debug, Serialize, Clone)]
pub enum OpenClaim4 {
    /*
     * No special rights to file.
     * Ordinary OPEN of the specified file.
     */
    /* CURRENT_FH: directory */
    CLAIM_NULL(Component4),
    /*
     * Right to the file established by an
     * open previous to server reboot.  File
     * identified by filehandle obtained at
     * that time rather than by name.
     */
    /* CURRENT_FH: file being reclaimed */
    CLAIM_PREVIOUS(OpenDelegationType4),

    /*
     * Right to file based on a delegation
     * granted by the server.  File is
     * specified by name.
     */
    /* CURRENT_FH: directory */
    CLAIM_DELEGATE_CUR(OpenClaimDelegateCur4),

    /*
     * Right to file based on a delegation
     * granted to a previous boot instance
     * of the client.  File is specified by name.
     */
    /* CURRENT_FH: directory */
    CLAIM_DELEGATE_PREV(Component4),
}

#[derive(Debug, Serialize, Clone)]
pub enum OpenDelegationType4 {
    OPEN_DELEGATE_NONE,
    OPEN_DELEGATE_READ,
    OPEN_DELEGATE_WRITE,
}

#[derive(Debug, Serialize, Clone)]
struct OpenClaimDelegateCur4 {
    delegate_stateid: StateId4,
    file: Component4,
}

#[derive(Debug, Serialize, Clone)]
pub struct StateId4 {
    seq_id: u32,
    #[serde(with = "serde_xdr::opaque_data::fixed_length")]
    other: [u8; NFS4_OTHER_SIZE],
}
