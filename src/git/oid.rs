/// 20 字节 SHA-1 Git object id。
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Oid(pub [u8; 20]);

impl Oid {
    pub const ZERO: Oid = Oid([0u8; 20]);

    pub fn from_slice(b: &[u8]) -> Oid {
        let mut a = [0u8; 20];
        a.copy_from_slice(&b[..20]);
        Oid(a)
    }

    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 20]
    }
}

/// 计算 Git object id：SHA-1(`<type> <len>\0<body>`)。
pub fn git_object_id(obj_type: &str, body: &[u8]) -> Oid {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(obj_type.as_bytes());
    h.update(b" ");
    h.update(body.len().to_string().as_bytes());
    h.update(b"\0");
    h.update(body);
    Oid(h.finalize().into())
}

pub fn oid_to_hex(o: &Oid) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(40);
    for b in &o.0 {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 0xf) as usize] as char);
    }
    s
}

pub fn hex_to_oid(s: &str) -> Option<Oid> {
    let s = s.trim();
    if s.len() < 4 {
        return None;
    }
    let mut a = [0u8; 20];
    for i in 0..20 {
        let hi = s.as_bytes().get(i * 2).and_then(|c| hexv(*c))?;
        let lo = s.as_bytes().get(i * 2 + 1).and_then(|c| hexv(*c))?;
        a[i] = (hi << 4) | lo;
    }
    Some(Oid(a))
}

fn hexv(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

impl std::fmt::Debug for Oid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", oid_to_hex(self))
    }
}

impl std::fmt::Display for Oid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", oid_to_hex(self))
    }
}

impl Default for Oid {
    fn default() -> Self {
        Oid::ZERO
    }
}
