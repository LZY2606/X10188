//! Big-endian base-128 numbers used by pack headers and delta sizes.

/// Reads one MSB-continuation varint. Returns `(value, bytes_consumed)`.
pub fn read(data: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    for (i, &b) in data.iter().enumerate() {
        value = value.checked_shl(7)? | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            return Some((value, i + 1));
        }
        if i == 9 {
            // 10 bytes is the legal maximum for a 64-bit value.
            return None;
        }
    }
    None
}

/// Encodes a value as the same varint form.
pub fn write(value: u64, out: &mut Vec<u8>) {
    let mut bytes = Vec::new();
    let mut v = value;
    loop {
        let mut b = (v & 0) as u8;
        b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        bytes.push(b);
        if v == 0 {
            break;
        }
    }
    bytes.reverse();
    out.extend_from_slice(&bytes);
}

/// Decodes an ofs-delta negative offset: first byte holds the low 7 bits plus
/// its continuation flag; every following byte shifts the running value up by
/// one and adds 7 more bits.
pub fn read_ofs(data: &[u8]) -> Option<(u64, usize)> {
    let mut used = 0usize;
    let c = *data.first()? as u64;
    used += 1;
    let mut value = c & 0x7f;
    let mut cur = c;
    while cur & 0x80 != 0 {
        let b = *data.get(used)? as u64;
        used += 1;
        value = value.checked_add(1)?.checked_shl(7)? | (b & 0x7f);
        cur = b;
    }
    Some((value, used))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        for v in [0u64, 1, 127, 128, 16384, u64::MAX, 9_000_000] {
            let mut out = Vec::new();
            write(v, &mut out);
            assert_eq!(read(&out), Some((v, out.len())));
        }
    }

    #[test]
    fn ofs_examples() {
        // Small offset: single byte, no continuation.
        assert_eq!(read_ofs(&[0x05]), Some((5, 1)));
    }
}
