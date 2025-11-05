use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use xdr_brk::{XDREnumDeserialize, XDREnumSerialize};

use crate::{
    NFSCRSInnerError, NFSClientSession, OpenOptions,
    fattr4::FAttr4,
    fattr4_utils::FAttr4Builder,
    nfs4_types::{
        AceFlag4, AceMask4, AceType4, BitMap4, ChangeId4, ClientId4, Component4, Count4, LinkText4,
        NFS4_OPAQUE_LIMIT, NFS4_OTHER_SIZE, NFSCookie4, NFSFH4, Offset4, SeqId4, SpecData4,
        Utf8StrMixed,
    },
    nfscrs_types::DirEntry,
    xdr_types::Opaque,
};

pub const TAG: &str = "nfscrstag";

#[repr(u32)]
#[derive(Debug, XDREnumSerialize)]
pub enum NFSArgOp4 {
    _PlaceHolder0,
    _PlaceHolder1,
    _PlaceHolder2,
    OP_ACCESS,                                       //ACCESS4args opaccess;
    OP_CLOSE(Close4Args),                                        //CLOSE4args opclose;
    OP_COMMIT,                                       //COMMIT4args opcommit;
    OP_CREATE(Create4Args),                          //CREATE4args opcreate;
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
    OP_OPEN_CONFIRM(OpenConfirm4Args),               //OPEN_CONFIRM4args opopen_confirm;
    OP_OPEN_DOWNGRADE,                               //OPEN_DOWNGRADE4args opopen_downgrade;
    OP_PUTFH(PutFH4Args),                            //PUTFH4args opputfh;
    OP_PUTPUBFH,                                     //void;
    OP_PUTROOTFH,                                    //void;
    OP_READ(Read4Args),                              //READ4args opread;
    OP_READDIR(ReadDir4Args),                        //READDIR4args opreaddir;
    OP_READLINK,                                     //void;
    OP_REMOVE,                                       //REMOVE4args opremove;
    OP_RENAME,                                       //RENAME4args oprename;
    OP_RENEW,                                        //RENEW4args oprenew;
    OP_RESTOREFH,                                    //void;
    OP_SAVEFH,                                       //void;
    OP_SECINFO,                                      //SECINFO4args opsecinfo;
    OP_SETATTR(SetAttr4Args),                                      //SETATTR4args opsetattr;
    OP_SETCLIENTID(SetClientId4Args),                //SETCLIENTID4args opsetclientid;
    OP_SETCLIENTID_CONFIRM(SetClientIdConfirm4Args), //SETCLIENTID_CONFIRM4args opsetclientid_confirm;
    OP_VERIFY,                                       //VERIFY4args opverify;
    OP_WRITE(Write4Args),                            //WRITE4args opwrite;
    OP_RELEASE_LOCKOWNER,                            //RELEASE_LOCKOWNER4args oprelease_lockowner;
    OP_ILLEGAL = 10044,                              //void;// well, this is actually 10044
}

#[derive(Debug, Deserialize)]
pub enum NFSResultOp4 {
    _PlaceHolder0,
    _PlaceHolder1,
    _PlaceHolder2,
    OP_ACCESS,
    OP_CLOSE(Close4Result),
    OP_COMMIT,
    OP_CREATE(Create4Result),
    OP_DELEGPURGE,
    OP_DELEGRETURN,
    OP_GETATTR(GetAttr4Result),
    OP_GETFH(GetFH4Result),
    OP_LINK,
    OP_LOCK,
    OP_LOCKT,
    OP_LOCKU,
    OP_LOOKUP(LookUp4Result),
    OP_LOOKUPP,
    OP_NVERIFY,
    OP_OPEN(Open4Result),
    OP_OPENATTR,
    OP_OPEN_CONFIRM(OpenConfirm4Result),
    OP_OPEN_DOWNGRADE,
    OP_PUTFH(PutFH4Result),
    OP_PUTPUBFH,
    OP_PUTROOTFH(PutRootFH4Result),
    OP_READ(Read4Result),
    OP_READDIR(ReadDir4Result),
    OP_READLINK,
    OP_REMOVE,
    OP_RENAME,
    OP_RENEW,
    OP_RESTOREFH,
    OP_SAVEFH,
    OP_SECINFO,
    OP_SETATTR(SetAttr4Result),
    OP_SETCLIENTID(SetClientId4Result),
    OP_SETCLIENTID_CONFIRM(SetClientIdConfirm4Result),
    OP_VERIFY,
    OP_WRITE(Write4Result),
    OP_RELEASE_LOCKOWNER,
    OP_ILLEGAL,
}

#[repr(u32)]
#[derive(Debug, Clone, XDREnumDeserialize)]
pub enum NFSStat4 {
    NFS4_OK = 0,                         /*                0 everything is okay       */
    NFS4ERR_PERM = 1,                    /*           1 caller not privileged    */
    NFS4ERR_NOENT = 2,                   /*          2 no such file/directory   */
    NFS4ERR_IO = 5,                      /*             5 hard I/O error           */
    NFS4ERR_NXIO = 6,                    /*           6 no such device           */
    NFS4ERR_ACCESS = 13,                 /*         13 access denied            */
    NFS4ERR_EXIST = 17,                  /*          17 file already exists      */
    NFS4ERR_XDEV = 18,                   /*           18 different file systems   */
    _NFSSTAT4_UNUSED = 19,               /*19  Unused/reserved        */
    NFS4ERR_NOTDIR = 20,                 /*         20 should be a directory    */
    NFS4ERR_ISDIR = 21,                  /*          21 should not be directory  */
    NFS4ERR_INVAL = 22,                  /*          22 invalid argument         */
    NFS4ERR_FBIG = 27,                   /*           27 file exceeds server max  */
    NFS4ERR_NOSPC = 28,                  /*          28 no space on file system  */
    NFS4ERR_ROFS = 30,                   /*           30 read-only file system    */
    NFS4ERR_MLINK = 31,                  /*          31 too many hard links      */
    NFS4ERR_NAMETOOLONG = 63,            /*    63 name exceeds server max  */
    NFS4ERR_NOTEMPTY = 66,               /*       66 directory not empty      */
    NFS4ERR_DQUOT = 69,                  /*          69 hard quota limit reached */
    NFS4ERR_STALE = 70,                  /*          70 file no longer exists    */
    NFS4ERR_BADHANDLE = 10001,           /*      10001 Illegal filehandle       */
    NFS4ERR_BAD_COOKIE = 10003,          /*     10003 READDIR cookie is stale  */
    NFS4ERR_NOTSUPP = 10004,             /*        10004 operation not supported  */
    NFS4ERR_TOOSMALL = 10005,            /*       10005 response limit exceeded  */
    NFS4ERR_SERVERFAULT = 10006,         /*    10006 undefined server error   */
    NFS4ERR_BADTYPE = 10007,             /*        10007 type invalid for CREATE  */
    NFS4ERR_DELAY = 10008,               /*          10008 file "busy" - retry      */
    NFS4ERR_SAME = 10009,                /*           10009 nverify says attrs same  */
    NFS4ERR_DENIED = 10010,              /*         10010 lock unavailable         */
    NFS4ERR_EXPIRED = 10011,             /*        10011 lock lease expired       */
    NFS4ERR_LOCKED = 10012,              /*         10012 I/O failed due to lock   */
    NFS4ERR_GRACE = 10013,               /*          10013 in grace period          */
    NFS4ERR_FHEXPIRED = 10014,           /*      10014 filehandle expired       */
    NFS4ERR_SHARE_DENIED = 10015,        /*   10015 share reserve denied     */
    NFS4ERR_WRONGSEC = 10016,            /*       10016 wrong security flavor    */
    NFS4ERR_CLID_INUSE = 10017,          /*     10017 clientid in use          */
    NFS4ERR_RESOURCE = 10018,            /*       10018 resource exhaustion      */
    NFS4ERR_MOVED = 10019,               /*          10019 file system relocated    */
    NFS4ERR_NOFILEHANDLE = 10020,        /*   10020 current FH is not set    */
    NFS4ERR_MINOR_VERS_MISMATCH = 10021, /* 10021 minor vers not supp */
    NFS4ERR_STALE_CLIENTID = 10022,      /* 10022 server has rebooted      */
    NFS4ERR_STALE_STATEID = 10023,       /*  10023 server has rebooted      */
    NFS4ERR_OLD_STATEID = 10024,         /*    10024 state is out of sync     */
    NFS4ERR_BAD_STATEID = 10025,         /*    10025 incorrect stateid        */
    NFS4ERR_BAD_SEQID = 10026,           /*      10026 request is out of seq.   */
    NFS4ERR_NOT_SAME = 10027,            /*       10027 verify - attrs not same  */
    NFS4ERR_LOCK_RANGE = 10028,          /*     10028 lock range not supported */
    NFS4ERR_SYMLINK = 10029,             /*        10029 should be file/directory */
    NFS4ERR_RESTOREFH = 10030,           /*      10030 no saved filehandle      */
    NFS4ERR_LEASE_MOVED = 10031,         /*    10031 some file system moved   */
    NFS4ERR_ATTRNOTSUPP = 10032,         /*    10032 recommended attr not sup */
    NFS4ERR_NO_GRACE = 10033,            /*       10033 reclaim outside of grace */
    NFS4ERR_RECLAIM_BAD = 10034,         /*    10034 reclaim error at server  */
    NFS4ERR_RECLAIM_CONFLICT = 10035,    /* 10035 conflict on reclaim    */
    NFS4ERR_BADXDR = 10036,              /*         10036 XDR decode failed        */
    NFS4ERR_LOCKS_HELD = 10037,          /*     10037 file locks held at CLOSE */
    NFS4ERR_OPENMODE = 10038,            /*       10038 conflict in OPEN and I/O */
    NFS4ERR_BADOWNER = 10039,            /*       10039 owner translation bad    */
    NFS4ERR_BADCHAR = 10040,             /*        10040 UTF-8 char not supported */
    NFS4ERR_BADNAME = 10041,             /*        10041 name not supported       */
    NFS4ERR_BAD_RANGE = 10042,           /*      10042 lock range not supported */
    NFS4ERR_LOCK_NOTSUPP = 10043,        /*   10043 no atomic up/downgrade   */
    NFS4ERR_OP_ILLEGAL = 10044,          /*     10044 undefined operation      */
    NFS4ERR_DEADLOCK = 10045,            /*       10045 file locking deadlock    */
    NFS4ERR_FILE_OPEN = 10046,           /*      10046 open file blocks op.     */
    NFS4ERR_ADMIN_REVOKED = 10047,       /*  10047 lock-owner state revoked */
    NFS4ERR_CB_PATH_DOWN = 10048,        /*10048  callback path down       */
}

#[derive(Debug, Deserialize)]
pub struct Compound4Result {
    pub status: NFSStat4,
    pub tag: String,
    pub resarray: Vec<NFSResultOp4>,
}

impl Compound4Result {
    pub fn is_status_ok(&self) -> bool {
        matches!(self.status, NFSStat4::NFS4_OK)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct GetAttr4Args {
    /* CURRENT_FH: directory or file */
    pub attr_request: BitMap4,
}

impl GetAttr4Args {
    pub fn new(attr_request: BitMap4) -> Self {
        Self { attr_request }
    }
    pub fn filetype() -> Self {
        Self {
            attr_request: BitMap4::from(&[1]),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct GetAttr4ResultOk {
    pub obj_attributes: FAttr4,
}

#[derive(Debug, XDREnumDeserialize)]
pub enum GetAttr4Result {
    NFS4_OK(GetAttr4ResultOk),
    #[default_arm]
    Default(u32),
}

pub const NFS4_VERIFIER_SIZE: usize = 8;

#[derive(Debug, Serialize, Deserialize, PartialEq, Default, Clone)]
pub struct Verifier4 {
    #[serde(with = "xdr_brk::fixed_length_bytes")]
    pub verifier4: [u8; NFS4_VERIFIER_SIZE],
}

impl Verifier4 {
    pub const fn zero() -> Self {
        Self {
            verifier4: [0; NFS4_VERIFIER_SIZE],
        }
    }
}

#[derive(Debug, XDREnumDeserialize)]
pub enum SetClientId4Result {
    NFS4_OK(SetClientIdResultOK),
    NFS4ERR_CLID_INUSE(ClientAddr4), //this has to be fix!
    #[default_arm]
    DefaultArm(u32), // we need to handle default arm in the result,
                                     //this will be done in xdr_brk_enum crate, which provides a attribute macro to do this.
}

#[derive(Debug, Serialize)]
pub struct NFSClientId4 {
    pub verifier: Verifier4,

    pub id: ByteBuf, // maximum length is NFS4_OPAQUE_LIMIT,1024.
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
    pub client: NFSClientId4,
    pub callback: CallBackClient4,
    pub callback_ident: u32,
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
    pub cb_program: u32,
    pub cb_location: ClientAddr4,
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
pub struct ClientAddr4 {
    /* see struct rpcb in RFC 1833 */
    pub r_netid: String, /* network id */
    pub r_addr: String,  /* universal address */
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
    pub tag: String,
    pub minorversion: u32,
    pub argarray: Vec<NFSArgOp4>,
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
        xdr_brk::to_bytes(&self).map_err(NFSCRSInnerError::from)
    }
}

impl Default for NFS4CompoundProcedure {
    fn default() -> Self {
        Self::new()
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
pub struct PutRootFH4Result {
    /* CURRENT_FH: root fh */
    pub status: NFSStat4,
}

#[derive(Debug, Serialize)]
pub struct ReadDir4Args {
    /* CURRENT_FH: directory */
    pub cookie: NFSCookie4,
    pub cookie_verf: Verifier4,
    pub dircount: Count4, // maximum number of bytes of directory information that should be returned
    pub maxcount: Count4, //
    pub attr_request: BitMap4,
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
    pub cookie: NFSCookie4,
    pub name: Component4,
    pub attrs: FAttr4,
    pub next_entry: Option<Box<Entry4>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DirList4 {
    pub entries: Option<Box<Entry4>>,
    pub eof: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ReadDir4ResultOk {
    pub cookie_verf: Verifier4,
    pub reply: DirList4,
}

impl ReadDir4ResultOk {
    pub fn readdir_complete(&self) -> bool {
        self.reply.eof
    }
    pub fn build_entries(&self) -> (Vec<DirEntry>, Option<u64>) {
        let mut entries = Vec::new();
        let mut next_e = &self.reply.entries;
        let mut cookie = None;
        while let Some(e) = next_e {
            entries.push(DirEntry::new(e.name.clone(), e.attrs.clone()));
            next_e = &e.next_entry;
            cookie = Some(e.cookie);
        }
        (entries, cookie)
    }
}

#[repr(u32)]
#[derive(Debug, XDREnumDeserialize, Clone)]
pub enum ReadDir4Result {
    NFS4_OK(ReadDir4ResultOk),
    #[default_arm]
    DefautlArm(u32),
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
pub struct LookUp4Result {
    status: NFSStat4,
}

#[derive(Debug, Serialize, Clone)]
pub struct Open4Args {
    pub seq_id: SeqId4,
    pub share_access: u32,
    pub share_deny: u32,
    pub owner: OpenOwner,
    pub open_how: OpenFlag4,
    pub claim: OpenClaim4,
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
    pub fn simple_open(session: &NFSClientSession, filename: &str) -> Self {
        let owner = OpenOwner {
            client_id: session.client_id,
            owner: ByteBuf::from(b"simple_open"),
        };
        Self {
            seq_id: 0,
            share_access: open_params::OPEN4_SHARE_ACCESS_READ,
            share_deny: 0,
            owner,
            open_how: OpenFlag4::OPEN4_NOCREATE,
            claim: OpenClaim4::CLAIM_NULL(ByteBuf::from(filename)),
        }
    }

    pub fn with_open_options(
        session: &NFSClientSession,
        filename: &str,
        open_options: OpenOptions,
    ) -> Self {
        let owner = OpenOwner {
            client_id: session.client_id,
            owner: ByteBuf::from(b"open"),
        };

        let share_access = if open_options.read && !open_options.write {
            open_params::OPEN4_SHARE_ACCESS_READ
        } else if !open_options.read && open_options.write {
            open_params::OPEN4_SHARE_ACCESS_WRITE
        } else {
            open_params::OPEN4_SHARE_ACCESS_BOTH
        };

        let mut fattr4_builder = FAttr4Builder::new();
        fattr4_builder.set_open_options(&open_options);
        let open_how = if open_options.create {
            OpenFlag4::OPEN4_CREATE(CreateHow4::UNCHECKED4(fattr4_builder.build()))
        } else {
            OpenFlag4::OPEN4_NOCREATE
        };

        Self {
            seq_id: 0,
            share_access,
            share_deny: 0,
            owner,
            open_how,
            claim: OpenClaim4::CLAIM_NULL(ByteBuf::from(filename)),
        }
    }
}

#[derive(Debug, Serialize, Clone)]
pub struct OpenOwner {
    pub client_id: ClientId4,
    pub owner: Opaque, // with length limit of NFS4_OPAQUE_LIMIT
}

#[derive(Debug, Clone, Serialize)]
#[repr(u32)]
pub enum OpenFlag4 {
    OPEN4_NOCREATE,
    OPEN4_CREATE(CreateHow4),
    Default,
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
pub struct OpenClaimDelegateCur4 {
    pub delegate_stateid: StateId4,
    pub file: Component4,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StateId4 {
    pub seq_id: u32,
    #[serde(with = "xdr_brk::fixed_length_bytes")]
    pub other: [u8; NFS4_OTHER_SIZE],
}

#[derive(Debug, Clone, Deserialize)]
pub struct OpenReadDelegation4 {
    pub state_id: StateId4,   /* Stateid for delegation */
    pub recall: bool, /* Pre-recalled flag for delegations obtained by reclaim (CLAIM_PREVIOUS) */
    pub permissions: NFSAce4, /* Defines users who don't need an ACCESS call to open for read */
}

#[derive(Debug, Clone, Deserialize)]
pub struct OpenWriteDelegation4 {
    pub state_id: StateId4, /* Stateid for delegation */
    pub recall: bool,       /* Pre-recalled flag for
                            delegations obtained
                            by reclaim
                            (CLAIM_PREVIOUS) */
    pub space_limit: NFSSpaceLimit4, /* Defines condition that
                                     the client must check to
                                     determine whether the
                                     file needs to be flushed
                                     to the server on close */

    pub permissions: NFSAce4, /* Defines users who don't
                              need an ACCESS call as
                              part of a delegated
                              open */
}

#[derive(Debug, Clone, Deserialize)]
pub struct NFSModifiedLimit4 {
    pub num_blocks: u32,
    pub bytes_per_block: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub enum NFSSpaceLimit4 {
    /* limit specified as file size */
    NFS_LIMIT_SIZE(u64),
    /* limit specified by number of blocks */
    NFS_LIMIT_BLOCKS(NFSModifiedLimit4),
}

#[derive(Debug, Clone, Deserialize)]
pub struct NFSAce4 {
    r#type: AceType4,
    flag: AceFlag4,
    access_mask: AceMask4,
    who: Utf8StrMixed,
}

#[derive(Debug, Clone, Deserialize)]
pub enum OpenDelegation4 {
    OPEN_DELEGATE_NONE,
    OPEN_DELEGATE_READ(OpenReadDelegation4),
    OPEN_DELEGATE_WRITE(OpenWriteDelegation4),
}

#[derive(Debug, XDREnumDeserialize)]
pub enum Open4Result {
    NFS4_OK(Open4ResultOk),
    #[default_arm]
    Default(u32),
}

#[derive(Debug, Deserialize)]
pub struct Open4ResultOk {
    pub state_id: StateId4,          /* Stateid for open */
    pub cinfo: ChangeInfo4,          /* Directory change info */
    pub rflags: u32,                 /* Result flags */
    pub attrset: BitMap4,            /* attribute set for create */
    pub delegation: OpenDelegation4, /* Info on any open delegation */
}

#[derive(Debug, Deserialize)]
pub struct ChangeInfo4 {
    pub atomic: bool,
    pub before: ChangeId4,
    pub after: ChangeId4,
}

#[derive(Debug, Deserialize)]
pub struct GetFH4ResultOk {
    pub object: NFSFH4,
}

#[derive(Debug, Deserialize)]
pub enum GetFH4Result {
    NFS4_OK(GetFH4ResultOk),
    Default,
}

#[derive(Debug, Serialize)]
pub struct Read4Args {
    pub state_id: StateId4,
    pub offset: Offset4,
    pub count: Count4,
}

#[derive(Debug, Deserialize)]
pub struct Read4ResultOk {
    pub eof: bool,
    pub data: Opaque,
}

#[derive(Debug, XDREnumDeserialize)]
pub enum Read4Result {
    NFS4_OK(Read4ResultOk),
    #[default_arm]
    Default(u32),
}

#[derive(Debug, Serialize)]
pub struct PutFH4Args {
    pub object: NFSFH4,
}

#[derive(Debug, Deserialize)]
pub struct PutFH4Result {
    /* CURRENT_FH: */
    pub status: NFSStat4,
}

#[derive(Debug, Serialize)]
pub struct OpenConfirm4Args {
    /* CURRENT_FH: opened file */
    pub open_stateid: StateId4,
    pub seq_id: SeqId4,
}

#[derive(Debug, Deserialize)]
pub struct OpenConfirm4ResultOk {
    pub open_stateid: StateId4,
}

#[derive(Debug, XDREnumDeserialize)]
pub enum OpenConfirm4Result {
    NFS4_OK(OpenConfirm4ResultOk),
    #[default_arm]
    Default(u32),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum StableHow4 {
    UNSTABLE4 = 0,
    DATA_SYNC4 = 1,
    FILE_SYNC4 = 2,
}

#[derive(Debug, Serialize)]
pub struct Write4Args {
    /* CURRENT_FH: file */
    pub state_id: StateId4,
    pub offset: Offset4,
    pub stable: StableHow4,
    pub data: Opaque,
}

#[derive(Debug, Deserialize)]
pub struct Write4ResultOk {
    pub count: Count4,
    pub committed: StableHow4,
    pub writeverf: Verifier4,
}

#[derive(Debug, XDREnumDeserialize)]
pub enum Write4Result {
    NFS4_OK(Write4ResultOk),
    #[default_arm]
    Default(u32),
}

mod nfs_ftype4 {
    pub const NF4REG: u32 = 1;
    pub const NF4DIR: u32 = 2;
    pub const NF4BLK: u32 = 3;
    pub const NF4CHR: u32 = 4;
    pub const NF4LNK: u32 = 5;
    pub const NF4SOCK: u32 = 6;
    pub const NF4FIFO: u32 = 7;
    pub const NF4ATTRDIR: u32 = 8;
    pub const NF4NAMEDATTR: u32 = 9;
}

#[repr(u32)]
#[derive(Debug, XDREnumSerialize)]
pub enum CreateType4 {
    NF4LNK(LinkText4) = nfs_ftype4::NF4LNK,
    NF4BLK(SpecData4) = nfs_ftype4::NF4BLK,
    NF4CHR(SpecData4) = nfs_ftype4::NF4CHR,
    NF4SOCK = nfs_ftype4::NF4SOCK,
    NF4FIFO = nfs_ftype4::NF4FIFO,
    NF4DIR = nfs_ftype4::NF4DIR,
    Default = nfs_ftype4::NF4ATTRDIR,
}

#[derive(Debug, Serialize)]
pub struct Create4Args {
    pub obj_type: CreateType4,
    pub obj_name: Component4,
    pub create_attrs: FAttr4,
}

#[derive(Debug, XDREnumDeserialize)]
pub enum Create4Result {
    NFS4_OK(Create4ResultOk),
    #[default_arm]
    Default(u32),
}

#[derive(Debug, Deserialize)]
pub struct Create4ResultOk {
    pub cinfo: ChangeInfo4,
    pub attr_set: BitMap4, /* attributes set */
}

#[derive(Debug, Serialize)]
pub struct SetAttr4Args {
    /* CURRENT_FH: target object */
    pub state_id: StateId4,
    pub obj_attributes: FAttr4,
}

#[derive(Debug, Deserialize)]
pub struct SetAttr4Result {
    pub status: NFSStat4,
    pub attrs_set: BitMap4,
}

#[derive(Debug, Serialize)]
pub struct Close4Args {
    /* CURRENT_FH: object */
    pub seq_id: SeqId4,
    pub open_state_id: StateId4,
}

#[derive(Debug, XDREnumDeserialize)]
pub enum Close4Result {
    NFS4_OK(StateId4),
    #[default_arm]
    Default(u32),
}