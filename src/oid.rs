//! 20-byte SHA-1 Git object id helpers.

/// A 20-byte SHA-1 git object id.
pub type Oid = [u8; 20];

pub fn to_hex(o: &Oid) -> String {
    let mut s = String::with_capacity(40);
    for b in o {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

pub fn from_hex(s: &str) -> Result<Oid, String> {
    let s = s.trim();
    if s.len() != 40 {
        return Err(format!("oid 长度不是 40: {}", s.len()));
    }
    let mut out = [0u8; 20];
 for i in 0..20 {
        let byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
        out[i] = byte;
    }
    Ok(out)
}

/// Recompute the git object id for a fully expanded object.
/// Header = `"<type> <len>\0"` followed by the content, fed through SHA-1.
pub fn git_object_id(kind: &str, content: &[u8]) -> Oid {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(kind.as_bytes());
    h.update(b" ");
    h.update(content.len().to_string().as_bytes());
    h.update([0u8]);
    h.update(content);
    let r = h.finalize();
    let mut o = [0u8; 20];
    o.copy_from_slice(&r);
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let s = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
        let o = from_hex(s).unwrap();
        assert_eq!(to_hex(&o), s);
    }

    #[test]
    fn empty_blob_id() {
        assert_eq!(
            to_hex(&git_object_id("blob", b"")),
            "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
        );
    }
}
