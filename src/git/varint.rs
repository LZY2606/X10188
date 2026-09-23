/// Read a pack entry header word starting at `pos`.
///
/// Returns `(type_code, declared_size, next_pos)`. The first byte packs the
/// MSB continuation flag, the 3-bit type, and the low 4 size bits; every
/// continuation byte contributes 7 more size bits.
pub fn read_entry_header(data: &[u8], mut pos: usize) -> Result<(u8, u64, usize), String> {
    let first = *data.get(pos).ok_or("unexpected EOF reading entry header")?;
    let type_code = (first >> 4) & 0b111;
    let mut size = (first & 0x0f) as u64;
    let mut shift = 4u32;
    pos += 1;
    let mut c = first;
    while c & 0x80 != 0 {
        c = *data.get(pos).ok_or("unexpected EOF in size continuation")?;
        size |= ((c & 0x7f) as u64) << shift;
        shift += 7;
        pos += 1;
    }
    Ok((type_code, size, pos))
}

/// Backward-compatible alias returning just the raw size word.
pub fn read_size(data: &[u8], pos: usize) -> Result<(u64, usize), String> {
    read_entry_header(data, pos).map(|(_, s, p)| (s, p))
}

/// Negative-offset encoding used by OFS_DELTA.
pub fn read_ofs_distance(data: &[u8], mut pos: usize) -> Result<(u64, usize), String> {
    let mut c = *data.get(pos).ok_or("unexpected EOF reading ofs")? as u64;
    let mut dist = c & 0x7f;
    pos += 1;
    while c & 0x80 != 0 {
        dist += 1;
        c = *data.get(pos).ok_or("unexpected EOF in ofs continuation")? as u64;
        pos += 1;
        dist = (dist << 7) | (c & 0x7f);
    }
    Ok((dist, pos))
}

/// Little-endian LEB128 used inside delta payloads.
pub fn read_leb128(data: &[u8], mut pos: usize) -> Result<(u64, usize), String> {
    let mut result: u64 = 0;
    let mut shift = 0;
    loop {
        let c = *data.get(pos).ok_or("unexpected EOF in LEB128")?;
        pos += 1;
        result |= ((c & 0x7f) as u64) << shift;
        if c & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 64 {
            return Err("LEB128 too large".into());
        }
    }
    Ok((result, pos))
}
