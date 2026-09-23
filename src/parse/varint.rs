//! Git's little-endian 7-bit varint encoding used in pack entry headers
//! and delta headers. Each byte contributes 7 bits; the high bit
//! means "more bytes follow".

#[derive(Debug, Clone)]
pub struct Varint {
    pub value: u64,
    /// Number of bytes the encoding occupied.
    pub len: usize,
}

pub fn read(data: &[u8]) -> Option<Varint> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    for (i, &b) in data.iter().enumerate() {
        let chunk = u64::from(b & 0x7f);
        result = result.checked_add(chunk.checked_shl(shift)?)?;
        shift += 7;
        if b & 0x80 == 0 {
            return Some(Varint { value: result, len: i + 1 });
        }
        if i >= 9 {
            return None;
        }
    }
    None
}

pub fn write(value: u64, out: &mut Vec<u8>) {
    let mut v = value;
    loop {
        let mut byte = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if v == 0 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        for v in [0u64, 1, 127, 128, 0x1000, 0x100_000, u64::MAX] {
            let mut buf = Vec::new();
            write(v, &mut buf);
            let got = read(&buf).unwrap();
            assert_eq!(got.value, v);
            assert_eq!(got.len(), buf.len());
        }
    }
}
