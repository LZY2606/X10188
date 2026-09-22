//! Git pack size varint (little-endian base-128, continuation in MSB).

/// Read one pack varint. Returns (value, bytes_consumed).
pub fn read(data: &[u8]) -> Option<(u64, usize)> {
    let mut shift = 0u32;
    let mut value: u64 = 0;
    for (i, &b) in data.iter().enumerate() {
        if shift >= 64 && (b & 0x7f) != 0 {
            return None;
        }
        value |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return Some((value, i + 1));
        }
    }
    None
}

/// Encode one pack varint.
pub fn write(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Read an ofs-delta negative-distance variable integer (big-endian base-128
/// with continuation bits). Returns (distance, bytes_consumed).
pub fn read_ofs_delta(data: &[u8]) -> Option<(u64, usize)> {
    if data.is_empty() || data[0] & 0x80 == 0 {
        return None;
    }
    let mut value = (data[0] & 0x7f) as u64;
    let mut i = 1usize;
    while data.get(i - 1)? & 0x80 != 0 {
        if i >= data.len() {
            return None;
        }
        value = value.checked_add(1)?.checked_shl(7)?;
        value |= (data[i] & 0x7f) as u64;
        i += 1;
    }
    Some((value, i))
}

/// Encode an ofs-delta negative distance (inverse of `read_ofs_delta`).
pub fn write_ofs_delta(mut distance: u64, out: &mut Vec<u8>) {
    let mut bytes = vec![(distance & 0x7f) as u8];
    distance >>= 7;
    while distance != 0 {
        distance -= 1;
        bytes.push((distance & 0x7f) as u8 | 0x80);
        distance >>= 7;
    }
    bytes.reverse();
    out.extend_from_slice(&bytes);
}
