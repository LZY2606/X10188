//! Git delta encoding (pack v2, OBJ_*_DELTA payload format).
//!
//! Payload layout:
//! ```text
//! base-size  (little-endian base-128 varint, non-terminating MSB set)
//! result-size (same)
//! instructions:
//!   high bit 0: insert  <n> literal bytes (n in 1..=127)
//!   high bit 1: copy    packed offset/size operands, size 0 means 0x10000
//!   byte 0: padding, illegal
//! ```

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeltaError {
    Truncated(&'static str),
    IllegalOpcode(u8, usize),
    SizeHeaderMismatch {
        declared: u64,
        actual: usize,
    },
    CopyOutOfBounds {
        offset: usize,
        len: usize,
        base_len: usize,
    },
    InsertOutOfBounds {
        wanted: usize,
        remaining: usize,
    },
    ResultSizeMismatch {
        declared: u64,
        actual: usize,
    },
}

impl std::fmt::Display for DeltaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeltaError::Truncated(w) => write!(f, "delta 数据截断: {}", w),
            DeltaError::IllegalOpcode(op, at) => {
                write!(f, "非法 delta 操作码 0x{:02x}（位于偏移 {}）", op, at)
            }
            DeltaError::SizeHeaderMismatch { declared, actual } => write!(
                f,
                "delta base 大小不匹配: 头声明 {} 实际 {}",
                declared, actual
            ),
            DeltaError::CopyOutOfBounds {
                offset,
                len,
                base_len,
            } => write!(
                f,
                "copy 越界: base[{}..{}] 但 base 长度 {}",
                offset,
                offset + len,
                base_len
            ),
            DeltaError::InsertOutOfBounds { wanted, remaining } => write!(
                f,
                "insert 越界: 需要 {} 字节，仅剩 {}",
                wanted, remaining
            ),
            DeltaError::ResultSizeMismatch { declared, actual } => write!(
                f,
                "delta 输出大小不匹配: 声明 {} 实际 {}",
                declared, actual
            ),
        }
    }
}

/// One delta instruction with its raw byte range inside the delta payload
/// and the ranges it reads/writes.
#[derive(Debug, Clone)]
pub struct InstrRecord {
    /// Raw byte interval `[start, end)` covering opcode and operands.
    pub raw_start: usize,
    pub raw_end: usize,
    pub kind: &'static str,
    /// Base interval read by a copy, `None` for inserts.
    pub src_start: Option<usize>,
    pub src_end: Option<usize>,
    /// Interval written into the result.
    pub dst_start: usize,
    pub dst_end: usize,
}

pub struct AppliedDelta {
    pub output: Vec<u8>,
    pub instrs: Vec<InstrRecord>,
}

fn read_size(data: &[u8], pos: &mut usize) -> Result<u64, DeltaError> {
    let mut size: u64 = 0;
    let mut shift = 0u32;
    loop {
        if *pos >= data.len() {
            return Err(DeltaError::Truncated("读取 size varint"));
        }
        let b = data[*pos];
        *pos += 1;
        size |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err(DeltaError::Truncated("size varint 过长"));
        }
    }
    Ok(size)
}

/// Apply a git delta against `base`.
pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<AppliedDelta, DeltaError> {
    let mut pos = 0;
    let base_size = read_size(delta, &mut pos)?;
    let result_size = read_size(delta, &mut pos)?;
    if base_size as usize != base.len() {
        return Err(DeltaError::SizeHeaderMismatch {
            declared: base_size,
            actual: base.len(),
        });
    }

    let mut out: Vec<u8> = Vec::with_capacity(result_size.min(1 << 30) as usize);
    let mut instrs = Vec::new();

    while pos < delta.len() {
        let raw_start = pos;
        let op = delta[pos];
        pos += 1;
        if op & 0x80 != 0 {
            // copy
            let mut offset: usize = 0;
            let mut size: usize = 0;
            let mut cp = 0u32;
            for i in 0..4u32 {
                if op & (1 << i) != 0 {
                    if pos >= delta.len() {
                        return Err(DeltaError::Truncated("copy offset 操作数"));
                    }
                    offset |= (delta[pos] as usize) << cp;
                    pos += 1;
                }
                cp += 8;
            }
            cp = 0;
            for i in 4..7u32 {
                if op & (1 << i) != 0 {
                    if pos >= delta.len() {
                        return Err(DeltaError::Truncated("copy size 操作数"));
                    }
                    size |= (delta[pos] as usize) << cp;
                    pos += 1;
                }
                cp += 8;
            }
            if size == 0 {
                size = 0x10000;
            }
            if offset.checked_add(size).map_or(true, |e| e > base.len()) {
                return Err(DeltaError::CopyOutOfBounds {
                    offset,
                    len: size,
                    base_len: base.len(),
                });
            }
            let dst_start = out.len();
            out.extend_from_slice(&base[offset..offset + size]);
            instrs.push(InstrRecord {
                raw_start,
                raw_end: pos,
                kind: "copy",
                src_start: Some(offset),
                src_end: Some(offset + size),
                dst_start,
                dst_end: dst_start + size,
            });
        } else if op != 0 {
            // insert
            let n = op as usize;
            if pos + n > delta.len() {
                return Err(DeltaError::InsertOutOfBounds {
                    wanted: n,
                    remaining: delta.len() - pos,
                });
            }
            let dst_start = out.len();
            out.extend_from_slice(&delta[pos..pos + n]);
            pos += n;
            instrs.push(InstrRecord {
                raw_start,
                raw_end: pos,
                kind: "insert",
                src_start: None,
                src_end: None,
                dst_start,
                dst_end: dst_start + n,
            });
        } else {
            return Err(DeltaError::IllegalOpcode(0, raw_start));
        }
    }

    if out.len() as u64 != result_size {
        return Err(DeltaError::ResultSizeMismatch {
            declared: result_size,
            actual: out.len(),
        });
    }
    Ok(AppliedDelta {
        output: out,
        instrs,
    })
}

/// Read the leading `base-size`/`result-size` pair without applying.
pub fn delta_header_sizes(delta: &[u8]) -> Result<(u64, u64, usize), DeltaError> {
    let mut pos = 0;
    let b = read_size(delta, &mut pos)?;
    let r = read_size(delta, &mut pos)?;
    Ok((b, r, pos))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc_size(mut n: usize) -> Vec<u8> {
        let mut v = Vec::new();
        loop {
            let mut b = (n & 0x7f) as u8;
            n >>= 7;
            if n != 0 {
                b |= 0x80;
            }
            v.push(b);
            if n == 0 {
                break;
            }
        }
        v
    }

    #[test]
    fn insert_then_copy() {
        let base = b"abcdefghij";
        let mut d = enc_size(base.len());
        d.extend(enc_size(7));
        d.push(3);
        d.extend_from_slice(b"XYZ");
        d.extend_from_slice(&[0x80 | 0x01 | 0x10, 2, 3]); // copy off=2 size=3
        let r = apply_delta(base, &d).unwrap();
        assert_eq!(r.output, b"XYZcde");
        assert_eq!(r.instrs.len(), 2);
        assert_eq!(r.instrs[0].kind, "insert");
        assert_eq!(r.instrs[1].src_start, Some(2));
    }

    #[test]
    fn copy_size_zero_means_64k() {
        let base = vec![b'q'; 0x10000];
        let mut d = enc_size(base.len());
        d.extend(enc_size(0x10000));
        d.extend_from_slice(&[0x81, 0, 0]); // offset=0, no size byte -> 0x10000
        let r = apply_delta(&base, &d).unwrap();
        assert_eq!(r.output.len(), 0x10000);
    }

    #[test]
    fn rejects_oob_copy() {
        let base = b"abc";
        let mut d = enc_size(3);
        d.extend(enc_size(5));
        d.extend_from_slice(&[0x80 | 0x01 | 0x10, 1, 5]);
        assert!(matches!(
            apply_delta(base, &d),
            Err(DeltaError::CopyOutOfBounds { .. })
        ));
    }

    #[test]
    fn rejects_bad_base_size() {
        let mut d = enc_size(99);
        d.extend(enc_size(0));
        assert!(matches!(
            apply_delta(b"abc", &d),
            Err(DeltaError::SizeHeaderMismatch { .. })
        ));
    }

    #[test]
    fn rejects_zero_opcode() {
        let mut d = enc_size(0);
        d.extend(enc_size(0));
        d.push(0);
        assert!(matches!(
            apply_delta(b"", &d),
            Err(DeltaError::IllegalOpcode(0, _))
        ));
    }
}
