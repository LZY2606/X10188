use crate::types::ObjType;
use sha1::{Digest, Sha1};

pub fn git_oid(kind: ObjType, data: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(kind.name().as_bytes());
    h.update(b" ");
    h.update(data.len().to_string().as_bytes());
    h.update(b"\0");
    h.update(data);
    crate::hexutil::to_hex(&h.finalize())
}

pub fn sha1_hex(data: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(data);
    crate::hexutil::to_hex(&h.finalize())
}

#[derive(Debug)]
pub enum LooseError {
    CorruptZlib,
    BadHeader,
}

pub struct LooseObject {
    pub kind: ObjType,
    pub data: Vec<u8>,
}

pub fn parse_loose(raw: &[u8]) -> Result<LooseObject, LooseError> {
    let inflated = crate::zlibutil::inflate_full(raw).map_err(|_| LooseError::CorruptZlib)?;
    let nul = inflated
        .iter()
        .position(|&b| b == 0)
        .ok_or(LooseError::BadHeader)?;
    let header = std::str::from_utf8(&inflated[..nul]).map_err(|_| LooseError::BadHeader)?;
    let mut parts = header.split(' ');
    let kind = parts
        .next()
        .and_then(ObjType::parse)
        .and_then(|t| t.base_type())
        .ok_or(LooseError::BadHeader)?;
    let size: usize = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or(LooseError::BadHeader)?;
    let data = inflated[nul + 1..].to_vec();
    if data.len() != size {
        return Err(LooseError::BadHeader);
    }
    Ok(LooseObject { kind, data })
}

pub fn read_varint(data: &[u8], mut pos: usize) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift = 0;
    loop {
        if pos >= data.len() || shift >= 64 {
            return None;
        }
        let b = data[pos];
        pos += 1;
        value |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Some((value, pos));
        }
        shift += 7;
    }
}

#[derive(Debug)]
pub enum DeltaError {
    Truncated,
    CopyOverflow,
    BadCopyRange,
    InsertOverflow,
    SizeMismatch,
    ZeroCopy,
}

#[derive(Default, Clone)]
pub struct OpRange {
    pub start: usize,
    pub end: usize,
}

pub struct DeltaReport {
    pub ops: Vec<(String, OpRange)>,
    pub instr_start: usize,
    pub instr_end: usize,
}

pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<(Vec<u8>, DeltaReport), DeltaError> {
    let (base_size, mut p) = read_varint(delta, 0).ok_or(DeltaError::Truncated)?;
    let (result_size, p2) = read_varint(delta, p).ok_or(DeltaError::Truncated)?;
    p = p2;
    if base_size as usize != base.len() {
        return Err(DeltaError::SizeMismatch);
    }
    if result_size > (1u64 << 40) {
        return Err(DeltaError::CopyOverflow);
    }
    let mut out = Vec::with_capacity(result_size as usize);
    let mut ops: Vec<(String, OpRange)> = Vec::new();
    let instr_start = p;
    while p < delta.len() {
        let op = delta[p];
        let start = p;
        p += 1;
        if op & 0x80 != 0 {
            let mut off: usize = 0;
            let mut len: usize = 0;
            for i in 0..4 {
                if op & (1 << i) != 0 {
                    if p >= delta.len() {
                        return Err(DeltaError::Truncated);
                    }
                    off |= (delta[p] as usize) << (8 * i);
                    p += 1;
                }
            }
            for i in 0..3 {
                if op & (1 << (4 + i)) != 0 {
                    if p >= delta.len() {
                        return Err(DeltaError::Truncated);
                    }
                    len |= (delta[p] as usize) << (8 * i);
                    p += 1;
                }
            }
            if len == 0 {
                len = 0x10000;
            }
            if len == 0 {
                return Err(DeltaError::ZeroCopy);
            }
            if off.checked_add(len).map(|e| e > base.len()).unwrap_or(true) {
                return Err(DeltaError::BadCopyRange);
            }
            out.extend_from_slice(&base[off..off + len]);
            ops.push((
                format!("copy@{}+{}", off, len),
                OpRange { start, end: p },
            ));
        } else if op != 0 {
            let len = op as usize;
            if p + len > delta.len() {
                return Err(DeltaError::Truncated);
            }
            out.extend_from_slice(&delta[p..p + len]);
            p += len;
            ops.push((
                format!("insert+{}", len),
                OpRange { start, end: p },
            ));
        } else {
            return Err(DeltaError::InsertOverflow);
        }
    }
    if out.len() != result_size as usize {
        return Err(DeltaError::SizeMismatch);
    }
    Ok((
        out,
        DeltaReport {
            ops,
            instr_start,
            instr_end: p,
        },
    ))
}
