//! Git delta instructions (used inside both OFS_DELTA and REF_DELTA objects):
//! size varints, COPY (0x80+) and INSERT (1..=127) commands.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeltaError {
    Truncated,
    InvalidOpcode,
    BadCopyRange,
    SizeMismatch { declared: usize, actual: usize },
    BaseSizeMismatch { declared: usize, actual: usize },
    OutputTooLarge(usize),
}

impl fmt::Display for DeltaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeltaError::Truncated => write!(f, "delta instructions truncated"),
            DeltaError::InvalidOpcode => write!(f, "invalid delta opcode 0"),
            DeltaError::BadCopyRange => write!(f, "copy range outside base or zero length"),
            DeltaError::SizeMismatch { declared, actual } => write!(
                f,
                "declared target size {declared} does not match produced size {actual}"
            ),
            DeltaError::BaseSizeMismatch { declared, actual } => write!(
                f,
                "declared base size {declared} does not match actual base size {actual}"
            ),
            DeltaError::OutputTooLarge(n) => write!(f, "delta output exceeds safety cap of {n} bytes"),
        }
    }
}

/// One decoded instruction with its exact byte range inside the delta payload.
#[derive(Debug, Clone)]
pub struct CmdRange {
    pub index: usize,
    /// Offset of the opcode byte in the delta payload.
    pub opcode_offset: usize,
    /// Total bytes the command occupies (opcode + operands, + literals).
    pub raw_len: usize,
    pub kind: CmdKind,
    pub dst_offset: usize,
    pub dst_len: usize,
}

#[derive(Debug, Clone)]
pub enum CmdKind {
    Copy { src_offset: usize, src_len: usize },
    Insert { src_len: usize },
}

/// Decode an LE-base-128 git varint. Returns (value, bytes consumed).
pub fn read_varint(data: &[u8], mut pos: usize) -> Result<(u64, usize), DeltaError> {
    let mut shift = 0u32;
    let mut value: u64 = 0;
    let start = pos;
    loop {
        if pos >= data.len() {
            return Err(DeltaError::Truncated);
        }
        let b = data[pos];
        pos += 1;
        value |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 64 {
            return Err(DeltaError::InvalidOpcode);
        }
    }
    Ok((value, pos - start))
}

pub const OUTPUT_CAP: usize = 512 * 1024 * 1024;

/// Apply `delta` to `base`, returning the rebuilt bytes plus per-command trace.
pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<(Vec<u8>, Vec<CmdRange>), DeltaError> {
    let (base_size, n1) = read_varint(delta, 0)?;
    if base_size as usize != base.len() {
        return Err(DeltaError::BaseSizeMismatch {
            declared: base_size as usize,
            actual: base.len(),
        });
    }
    let (result_size, n2) = read_varint(delta, n1)?;
    if result_size as usize > OUTPUT_CAP {
        return Err(DeltaError::OutputTooLarge(OUTPUT_CAP));
    }
    let result_size = result_size as usize;
    let mut out = Vec::with_capacity(result_size.min(64 * 1024 * 1024));
    let mut pos = n1 + n2;
    let mut cmds = Vec::new();
    let mut index = 0usize;

    while pos < delta.len() {
        let opcode_offset = pos;
        let op = delta[pos];
        pos += 1;
        if op & 0x80 != 0 {
            let mut cp_off: u32 = 0;
            let mut cp_size: u32 = 0;
            let mut raw_len = 1usize;
            if op & 0x01 != 0 {
                if pos >= delta.len() {
                    return Err(DeltaError::Truncated);
                }
                cp_off |= delta[pos] as u32;
                pos += 1;
                raw_len += 1;
            }
            if op & 0x02 != 0 {
                if pos >= delta.len() {
                    return Err(DeltaError::Truncated);
                }
                cp_off |= (delta[pos] as u32) << 8;
                pos += 1;
                raw_len += 1;
            }
            if op & 0x04 != 0 {
                if pos >= delta.len() {
                    return Err(DeltaError::Truncated);
                }
                cp_off |= (delta[pos] as u32) << 16;
                pos += 1;
                raw_len += 1;
            }
            if op & 0x08 != 0 {
                if pos >= delta.len() {
                    return Err(DeltaError::Truncated);
                }
                cp_off |= (delta[pos] as u32) << 24;
                pos += 1;
                raw_len += 1;
            }
            if op & 0x10 != 0 {
                if pos >= delta.len() {
                    return Err(DeltaError::Truncated);
                }
                cp_size |= delta[pos] as u32;
                pos += 1;
                raw_len += 1;
            }
            if op & 0x20 != 0 {
                if pos >= delta.len() {
                    return Err(DeltaError::Truncated);
                }
                cp_size |= (delta[pos] as u32) << 8;
                pos += 1;
                raw_len += 1;
            }
            if op & 0x40 != 0 {
                if pos >= delta.len() {
                    return Err(DeltaError::Truncated);
                }
                cp_size |= (delta[pos] as u32) << 16;
                pos += 1;
                raw_len += 1;
            }
            if cp_size == 0 {
                cp_size = 0x10000;
            }
            let s = cp_off as usize;
            let l = cp_size as usize;
            if l == 0 || s.checked_add(l).map_or(true, |end| end > base.len()) {
                return Err(DeltaError::BadCopyRange);
            }
            let dst_offset = out.len();
            out.extend_from_slice(&base[s..s + l]);
            cmds.push(CmdRange {
                index,
                opcode_offset,
                raw_len,
                kind: CmdKind::Copy { src_offset: s, src_len: l },
                dst_offset,
                dst_len: l,
            });
            index += 1;
        } else if op != 0 {
            let l = op as usize;
            if pos + l > delta.len() {
                return Err(DeltaError::Truncated);
            }
            let dst_offset = out.len();
            out.extend_from_slice(&delta[pos..pos + l]);
            cmds.push(CmdRange {
                index,
                opcode_offset,
                raw_len: 1 + l,
                kind: CmdKind::Insert { src_len: l },
                dst_offset,
                dst_len: l,
            });
            pos += l;
            index += 1;
        } else {
            return Err(DeltaError::InvalidOpcode);
        }
        if out.len() > result_size {
            return Err(DeltaError::SizeMismatch {
                declared: result_size,
                actual: out.len(),
            });
        }
    }

    if out.len() != result_size {
        return Err(DeltaError::SizeMismatch {
            declared: result_size,
            actual: out.len(),
        });
    }
    Ok((out, cmds))
}

fn write_varint(out: &mut Vec<u8>, mut v: usize) {
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
}

/// Minimal delta encoder used by the self-contained test fixture builder:
/// emits INSERT / COPY commands (matches of >=4 bytes), no git binary needed.
pub fn encode_delta(base: &[u8], target: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    write_varint(&mut out, base.len());
    write_varint(&mut out, target.len());

    let mut i = 0usize;
    while i < target.len() {
        let mut best: Option<(usize, usize)> = None;
        if base.len() >= 4 && i + 4 <= target.len() {
            let max_match = (target.len() - i).min(0xffff).min(base.len());
            'search: for s in 0..=base.len().saturating_sub(4) {
                let mut l = 0usize;
                while l < max_match && base[s + l] == target[i + l] {
                    l += 1;
                }
                if l >= 4 && best.map_or(true, |(_, bl)| l > bl) {
                    best = Some((s, l));
                    if l == max_match {
                        break 'search;
                    }
                }
            }
        }
        if let Some((s, l)) = best {
            emit_copy(&mut out, s, l);
            i += l;
        } else {
            let l = (target.len() - i).min(127);
            out.push(l as u8);
            out.extend_from_slice(&target[i..i + l]);
            i += l;
        }
    }
    out
}

fn emit_copy(out: &mut Vec<u8>, offset: usize, size: usize) {
    let mut op = 0x80u8;
    let mut operand = 0u32;
    if offset & 0xff != 0 {
        op |= 0x01;
        operand |= (offset & 0xff) as u32;
    }
    if offset & 0xff00 != 0 {
        op |= 0x02;
        operand |= ((offset >> 8) & 0xff) as u32;
    }
    if offset & 0xff_0000 != 0 {
        op |= 0x04;
        operand |= ((offset >> 16) & 0xff) as u32;
    }
    if offset & 0xff00_0000 != 0 {
        op |= 0x08;
        operand |= ((offset >> 24) & 0xff) as u32;
    }
    out.push(op);
    let mut mask = 0x01u8;
    for _ in 0..4 {
        if op & mask != 0 {
            out.push((operand & 0xff) as u8);
            operand >>= 8;
        }
        mask <<= 1;
    }

    let real_size = if size == 0x10000 { 0 } else { size };
    let mut sop = 0u8;
    if real_size & 0xff != 0 {
        sop |= 0x10;
    }
    if real_size & 0xff00 != 0 {
        sop |= 0x20;
    }
    if real_size & 0xff_0000 != 0 {
        sop |= 0x40;
    }
    op = 0x80 | sop;
    let mut operand = real_size as u32;
    out.push(op);
    let mut mask = 0x10u8;
    for _ in 0..3 {
        if op & mask != 0 {
            out.push((operand & 0xff) as u8);
            operand >>= 8;
        }
        mask <<= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_insert_copy() {
        let base = b"hello world, this is the base text";
        let target = b"hello world, this is the TARGET text!!";
        let d = encode_delta(base, target);
        let (out, cmds) = apply_delta(base, &d).unwrap();
        assert_eq!(out, target);
        assert!(cmds.iter().any(|c| matches!(c.kind, CmdKind::Copy { .. })));
    }

    #[test]
    fn long_copy_uses_zero_size() {
        let base = vec![b'x'; 0x10000];
        let mut target = base.clone();
        target.push(b'!');
        let d = encode_delta(&base, &target);
        let (out, _) = apply_delta(&base, &d).unwrap();
        assert_eq!(out, target);
    }

    #[test]
    fn rejects_bad_size_and_opcode() {
        let mut d = vec![2u8, 2u8];
        d.extend_from_slice(b"ab");
        assert_eq!(
            apply_delta(b"x", &d).unwrap_err(),
            DeltaError::BaseSizeMismatch { declared: 2, actual: 1 }
        );
        let d2 = vec![0u8, 0u8, 0u8];
        assert_eq!(apply_delta(b"", &d2).unwrap_err(), DeltaError::InvalidOpcode);
    }
}
