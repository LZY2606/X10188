//! Git little-endian base-128 varints (used in pack headers and deltas).

pub fn read_uleb128(data: &[u8], mut pos: usize) -> Result<(u64, usize), String> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    loop {
        if pos >= data.len() {
            return Err("unexpected end while reading varint".into());
        }
        let byte = data[pos];
        pos += 1;
        result |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok((result, pos));
        }
        shift += 7;
        if shift >= 64 {
            return Err("varint too long".into());
        }
    }
}

/// Negative-ofs-delta distance encoding from pack files.
pub fn read_ofs_distance(data: &[u8], mut pos: usize) -> Result<(u64, usize), String> {
    if pos >= data.len() {
        return Err("unexpected end while reading ofs distance".into());
    }
    let mut byte = data[pos];
    pos += 1;
    let mut value = (byte & 0x7f) as u64;
    while byte & 0x80 != 0 {
        if pos >= data.len() {
            return Err("unexpected end while reading ofs distance".into());
        }
        value = value
            .checked_add(1)
            .ok_or("ofs distance overflow")?
            .checked_shl(7)
            .ok_or("ofs distance overflow")?;
        byte = data[pos];
        pos += 1;
        value |= (byte & 0x7f) as u64;
    }
    Ok((value, pos))
}

pub fn write_uleb128(mut value: u64, out: &mut Vec<u8>) {
    let mut bytes = Vec::new();
    loop {
        let mut b = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            b |= 0x80;
        }
        bytes.push(b);
        if value == 0 {
            break;
        }
    }
    bytes.reverse();
    out.extend_from_slice(&bytes);
}
