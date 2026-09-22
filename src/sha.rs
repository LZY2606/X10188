use crate::types::Oid20;
use sha1::{Digest, Sha1};

pub fn sha1(data: &[u8]) -> Oid20 {
    let mut h = Sha1::new();
    h.update(data);
    h.finalize().into()
}
