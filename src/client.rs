use rand::Rng;

use crate::{nfsv4_ops::Verifier4, xdr_types::Opaque};

pub struct ClientOwner4 {
    pub co_verifier: Verifier4,
    pub co_ownerid: Opaque, // with size limit: NFS4_OPAQUE_LIMIT
}

impl ClientOwner4 {
    fn new(co_verifier: Verifier4, co_ownerid: Opaque) -> Self {
        Self {
            co_verifier,
            co_ownerid,
        }
    }
    fn with_co_ownerid(co_ownerid: Opaque) -> Self {
        let mut rng = rand::rng();
        Self {
            co_verifier: rng.random(),
            co_ownerid,
        }
    }
}
