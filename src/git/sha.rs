use sha1::{Digest, Sha1};

pub fn sha1_hex(data: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(data);
    hex::encode(h.finalize())
}

pub fn object_id(kind: &str, body: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(kind.as_bytes());
    h.update(b" ");
    h.update(body.len().to_string().as_bytes());
    h.update(b"\0");
    h.update(body);
    hex::encode(h.finalize())
}

pub fn raw_sha1(data: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(data);
    let out = h.finalize();
    let mut a = [0u8; 20];
    a.copy_from_slice(&out);
    a
}
