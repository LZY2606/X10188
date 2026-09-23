//! Git's little-endian-base-128 size encoding used in packs and deltas.

/// Read a size-encoded value starting at `data[pos]`.
/// Returns `(value, bytes_consumed)`.
pub fn read_size_encoding(data: &[u8], mut pos: usize) -> Result<(u64, usize), String> {
    let mut shift = 0u32;
    let start = pos;
    let mut result: u64 = 0;
    loop {
        if pos >= data.len() {
            return Err("size encoding truncated".into());
        }
        let byte = data[pos];
        pos += 1;
        result |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err("size encoding too long".into());
        }
    }
    Ok((result, pos - start))
}

/// Encode a value the same way (used by the in-memory pack builder).
pub fn write_size_encoding(mut value: u64, first_byte: u8, out: &mut Vec<u8>) {
    let mut first = true;
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if first {
            byte |= first_byte;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            first = false;
        } else if value != 0 {
            out.push(byte | 0x80);
        } else {
            out.push(byte);
            break;
        }
        if value == 0 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_sizes() {
        for &v in &[0u64, 1, 2, 127, 128, 255, 1024, 65535, 1 << 30] {
            let mut buf = Vec::new();
            write_size_encoding(v, 0, &mut buf);
            let (got, used) = read_size_encoding(&buf, 0).unwrap();
            assert_eq!(got, v);
            assert_eq!(used, buf.len());
        }
    }

    #[test]
    fn truncated() {
        assert!(read_size_encoding(&[0x80], 0).is_err());
    }
}
