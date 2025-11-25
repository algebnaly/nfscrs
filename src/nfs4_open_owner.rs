use serde_bytes::ByteBuf;

pub struct OpenOwner {
    pub owner: ByteBuf,
    pub seq_id: u32,
}
