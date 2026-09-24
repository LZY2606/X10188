use sha1::{Digest, Sha1};

/// Git object id = sha1(b"{type} {len}\0{content}")
pub fn git_object_id(obj_type: &str, content: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(obj_type.as_bytes());
    h.update(b" ");
    h.update(content.len().to_string().as_bytes());
    h.update(b"\0");
    h.update(content);
    hex(&h.finalize())
}

/// Generic content fingerprint (also sha1, kept separate name for provenance).
pub fn content_fingerprint(data: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(data);
    hex(&h.finalize())
}

pub fn sha1_bytes(data: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(data);
    let out = h.finalize();
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&out);
    arr
}

pub fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// crc32 as git idx stores it.
pub fn crc32(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}
