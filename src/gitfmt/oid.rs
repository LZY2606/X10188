const HEX: [char; 16] = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Oid(pub [u8; 20]);

fn hexv(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

impl Oid {
    pub fn zero() -> Self {
        Oid([0u8; 20])
    }
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 20]
    }
    pub fn from_hex(s: &str) -> Option<Self> {
        let b = s.as_bytes();
        if b.len() != 40 {
            return None;
        }
        let mut out = [0u8; 20];
        for i in 0..20 {
            let hi = hexv(b[i * 2])?;
            let lo = hexv(b[i * 2 + 1])?;
            out[i] = hi << 4 | lo;
        }
        Some(Oid(out))
    }
    pub fn hex(&self) -> String {
        let mut s = String::with_capacity(40);
        for b in &self.0 {
            s.push(HEX[(b >> 4) as usize]);
            s.push(HEX[(b & 0xf) as usize]);
        }
        s
    }
    pub fn bytes(&self) -> &[u8; 20] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hex_roundtrip() {
        let s = "0123456789abcdef000102030405060708090a0b";
        let o = Oid::from_hex(s).unwrap();
        assert_eq!(o.hex(), s);
        assert_eq!(Oid::from_hex("nope"), None);
    }
}
