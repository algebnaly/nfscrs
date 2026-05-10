use minibserde::Encode;
use rand::Rng;

use crate::{nfsv4_ops::Verifier4, xdr_types::Opaque};

#[derive(Debug, Encode, Clone)]
pub struct ClientOwner4 {
    pub co_verifier: Verifier4,
    // co_ownerid must be consistent across incarnations,
    // since this library have no stable method to generate consistent co_ownerid,
    // it is library user's reponsibility to provide consistent co_ownerid.
    pub co_ownerid: Opaque, // with size limit: NFS4_OPAQUE_LIMIT
}

impl ClientOwner4 {
    pub fn new(co_verifier: Verifier4, co_ownerid: Opaque) -> Self {
        Self {
            co_verifier,
            co_ownerid,
        }
    }
    pub fn with_co_ownerid(co_ownerid: Opaque) -> Self {
        let mut rng = rand::rng();
        Self {
            co_verifier: rng.random(),
            co_ownerid,
        }
    }
}
