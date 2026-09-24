use crate::error::{Error, ErrorCode, R};

pub fn oid_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

pub fn oid_sha1(kind: &str, content: &[u8]) -> [u8; 20] {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(kind.as_bytes());
    h.update(b" ");
    h.update(content.len().to_string().as_bytes());
    h.update(b"\0");
    h.update(content);
    let out = h.finalize();
    let mut oid = [0u8; 20];
    oid.copy_from_slice(&out);
    oid
}

/// Git variable-length little-endian base-128 size encoding (used in loose
/// objects and delta headers).
pub fn read_var_size(buf: &[u8], mut pos: usize) -> R<(u64, usize)> {
    let mut size: u64 = 0;
    let mut shift = 0u32;
    loop {
        if pos >= buf.len() {
            return Err(Error::new(ErrorCode::PackTruncated, "varint runs past buffer"));
        }
        let b = buf[pos];
        pos += 1;
        size |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err(Error::new(ErrorCode::DeltaBadInstruction, "varint too long"));
        }
    }
    Ok((size, pos))
}

pub fn write_var_size(mut size: u64, out: &mut Vec<u8>) {
    loop {
        let mut b = (size & 0x7f) as u8;
        size >>= 7;
        if size != 0 {
            b |= 0x80;
        }
        out.push(b);
        if size == 0 {
            break;
        }
    }
}

/// Parse a pack entry header at `pos`: returns (type_bits, inflated_size, header_len).
pub fn read_pack_header_byte(buf: &[u8], pos: usize) -> R<(u8, u64, usize)> {
    if pos >= buf.len() {
        return Err(Error::new(ErrorCode::PackEntryTruncated, "no header byte"));
    }
    let first = buf[pos];
    let kind = (first >> 4) & 0x7;
    let mut size = (first & 0x0f) as u64;
    let mut p = pos + 1;
    let mut shift = 4u32;
    let mut cont = first & 0x80 != 0;
    while cont {
        if p >= buf.len() {
            return Err(Error::new(ErrorCode::PackEntryTruncated, "header continuation"));
        }
        let b = buf[p];
        p += 1;
        size |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        cont = b & 0x80 != 0;
    }
    Ok((kind, size, p - pos))
}

/// Decode the negative-relative offset used by OFS_DELTA entries.
pub fn read_ofs_distance(buf: &[u8], mut pos: usize) -> R<(u64, usize)> {
    let start = pos;
    if pos >= buf.len() {
        return Err(Error::new(ErrorCode::PackEntryTruncated, "ofs byte missing"));
    }
    let mut b = buf[pos];
    pos += 1;
    let mut ofs = (b & 0x7f) as u64;
    while b & 0x80 != 0 {
        if pos >= buf.len() {
            return Err(Error::new(ErrorCode::PackEntryTruncated, "ofs continuation"));
        }
        b = buf[pos];
        pos += 1;
        ofs = ofs.wrapping_add(1);
        ofs = (ofs << 7) | ((b & 0x7f) as u64);
    }
    Ok((ofs, pos - start))
}
