pub fn read_varint(data: &[u8]) -> Result<(u64, usize), String> {
    let mut v: u64 = 0;
    let mut n = 0usize;
    loop {
        if n >= data.len() {
            return Err("varint truncated".into());
        }
        let b = data[n];
        n += 1;
        let part = (b & 0x7f) as u64;
        v = v
            .checked_shl(7)
            .and_then(|x| x.checked_add(part))
            .ok_or_else(|| "varint overflow".to_string())?;
        if b & 0x80 == 0 {
            return Ok((v, n));
        }
        if n >= 10 {
            return Err("varint too long".into());
        }
    }
}

pub fn write_varint(mut v: u64, out: &mut Vec<u8>) {
    let mut bytes = vec![(v & 0x7f) as u8];
    v >>= 7;
    while v != 0 {
        bytes.push((v & 0x7f) as u8 | 0x80);
        v >>= 7;
    }
    bytes.reverse();
    out.extend_from_slice(&bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip() {
        for &x in &[0u64, 1, 127, 128, 255, 300, 16383, 16384, u64::MAX] {
            let mut b = Vec::new();
            write_varint(x, &mut b);
            let (v, n) = read_varint(&b).unwrap();
            assert_eq!(v, x);
            assert_eq!(n, b.len());
        }
    }
}
