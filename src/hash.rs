//! Git 对象 id 重算：`SHA1("<type> <len>\0<body>")`。

use sha1::{Digest, Sha1};

use crate::types::ObjType;

/// 按 Git 规则计算对象 id。类型必须是已还原的四种对象之一。
pub fn git_object_id(obj_type: ObjType, body: &[u8]) -> Option<[u8; 20]> {
    let name = obj_type.git_name()?;
    let mut h = Sha1::new();
    h.update(name.as_bytes());
    h.update(b" ");
    h.update(body.len().to_string().as_bytes());
    h.update([0u8]);
    h.update(body);
    let out = h.finalize();
    let mut oid = [0u8; 20];
    oid.copy_from_slice(&out);
    Some(oid)
}

pub fn hex20(oid: &[u8; 20]) -> String {
    hex::encode(oid)
}

/// 计算任意字节切片的 SHA1（用于 pack trailer、idx 校验）。
pub fn sha1_hex(data: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// 把 hex oid 转成 20 字节；非法返回 None。
pub fn parse_oid_hex(s: &str) -> Option<[u8; 20]> {
    let v = hex::decode(s).ok()?;
    if v.len() != 20 {
        return None;
    }
    let mut o = [0u8; 20];
    o.copy_from_slice(&v);
    Some(o)
}
