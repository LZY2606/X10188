/// pack 头里的变长整数（msb 续位，低 3 位是类型，低 4 位是大小低位）。
pub fn read_pack_header_size(data: &[u8], pos: &mut usize) -> Option<(u8, u64)> {
    if *pos >= data.len() {
        return None;
    }
    let first = data[*pos];
    *pos += 1;
    let kind = (first >> 4) & 0x07;
    let mut size = (first & 0x0f) as u64;
    let mut shift = 4u32;
    let mut b = first;
    while b & 0x80 != 0 {
        if *pos >= data.len() {
            return None;
        }
        b = data[*pos];
        *pos += 1;
        size |= ((b & 0x7f) as u64) << shift;
        shift += 7;
    }
    Some((kind, size))
}

/// ofs-delta 基偏移的负距离编码。返回 (distance, consumed)。
pub fn read_ofs_distance(data: &[u8], pos: &mut usize) -> Option<u64> {
    if *pos >= data.len() {
        return None;
    }
    let mut b = data[*pos];
    *pos += 1;
    let mut dist = (b & 0x7f) as u64;
    while b & 0x80 != 0 {
        if *pos >= data.len() {
            return None;
        }
        b = data[*pos];
        *pos += 1;
        dist = dist.wrapping_add(1);
        dist = (dist << 7) | (b & 0x7f) as u64;
    }
    Some(dist)
}

pub fn u32be(data: &[u8], pos: usize) -> Option<u32> {
    if pos + 4 > data.len() {
        return None;
    }
    Some(u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap()))
}

pub fn crc32(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}
