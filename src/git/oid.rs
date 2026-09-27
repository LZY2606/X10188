//! Git object id (SHA-1 over `<type> <len>\0<content>`)。

use sha1::{Digest, Sha1};

use super::ObjType;

pub fn git_object_id(ty: ObjType, content: &[u8]) -> [u8; 20] {
    let header = format!("{} {}\0", ty.code(), content.len());
    let mut h = Sha1::new();
    Digest::update(&mut h, header.as_bytes());
    Digest::update(&mut h, content);
    let r = h.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&r);
    out
}

pub fn sha1_bytes(data: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    Digest::update(&mut h, data);
    let r = h.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&r);
    out
}
