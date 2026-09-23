//! Git copy/insert delta application (v2 pack format).
//!
//! Wire format:
//! ```text
//! base-size     (size encoding)
//! result-size   (size encoding)
//! commands...   zero or more of:
//!   0x80..=0xff  COPY: bitmask selects offset(4)/size(3) little-endian bytes
//!   0x01..=0x7f  INSERT: take that many literal bytes
//!   0x00         reserved / invalid
//! ```

use crate::git::varint::read_size_encoding;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstrRange {
    pub index: u32,
    pub kind: &'static str,
    pub delta_off: usize,
    pub delta_len: usize,
    pub copy_off: u64,
    pub copy_size: u64,
}

#[derive(Debug, Clone)]
pub struct AppliedDelta {
    pub result: Vec<u8>,
    pub base_size_declared: u64,
    pub result_size_declared: u64,
    pub copy_count: u32,
    pub insert_count: u32,
    pub instr: Vec<InstrRange>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DeltaError {
    Truncated(String),
    BaseSizeMismatch { declared: u64, actual: u64 },
    ResultSizeMismatch { declared: u64, actual: u64 },
    CopyOutOfRange { off: u64, size: u64, base_len: u64 },
    InvalidZeroOpcode,
    OutputExceedsDeclared,
}

impl std::fmt::Display for DeltaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeltaError::Truncated(s) => write!(f, "delta truncated: {s}"),
            DeltaError::BaseSizeMismatch { declared, actual } => write!(
                f,
                "delta base-size mismatch: declared {declared}, actual base {actual}"
            ),
            DeltaError::ResultSizeMismatch { declared, actual } => write!(
                f,
                "delta result-size mismatch: declared {declared}, produced {actual}"
            ),
            DeltaError::CopyOutOfRange { off, size, base_len } => write!(
                f,
                "delta copy out of range: offset {off} size {size} vs base {base_len}"
            ),
            DeltaError::InvalidZeroOpcode => f.write_str("delta opcode 0 is invalid"),
            DeltaError::OutputExceedsDeclared => {
                f.write_str("delta output exceeded declared result size")
            }
        }
    }
}

impl std::error::Error for DeltaError {}

pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<AppliedDelta, DeltaError> {
    let mut pos = 0usize;
    let (base_declared, n1) = read_size_encoding(delta, 0).map_err(DeltaError::Truncated)?;
    pos += n1;
    let (result_declared, n2) =
        read_size_encoding(delta, pos).map_err(DeltaError::Truncated)?;
    pos += n2;

    if base_declared != base.len() as u64 {
        return Err(DeltaError::BaseSizeMismatch {
            declared: base_declared,
            actual: base.len() as u64,
        });
    }

    let mut out: Vec<u8> = Vec::with_capacity(result_declared.min(64 * 1024 * 1024) as usize);
    let mut copy_count = 0u32;
    let mut insert_count = 0u32;
    let mut instr: Vec<InstrRange> = Vec::new();
    let mut index = 0u32;

    while pos < delta.len() {
        let opcode = delta[pos];
        let instr_start = pos;
        pos += 1;
        if opcode & 0x80 != 0 {
            let mut cp_off: u32 = 0;
            let mut cp_size: u32 = 0;
            for bit in 0..4u8 {
                if opcode & (1 << bit) != 0 {
                    if pos >= delta.len() {
                        return Err(DeltaError::Truncated("copy offset bytes".into()));
                    }
                    cp_off |= (delta[pos] as u32) << (bit * 8);
                    pos += 1;
                }
            }
            for bit in 0..3u8 {
                if opcode & (1 << (4 + bit)) != 0 {
                    if pos >= delta.len() {
                        return Err(DeltaError::Truncated("copy size bytes".into()));
                    }
                    cp_size |= (delta[pos] as u32) << (bit * 8);
                    pos += 1;
                }
            }
            if cp_size == 0 {
                cp_size = 0x10000;
            }
            let end = cp_off as u64 + cp_size as u64;
            if end > base.len() as u64 {
                return Err(DeltaError::CopyOutOfRange {
                    off: cp_off as u64,
                    size: cp_size as u64,
                    base_len: base.len() as u64,
                });
            }
            if out.len() as u64 + cp_size as u64 > result_declared {
                return Err(DeltaError::OutputExceedsDeclared);
            }
            out.extend_from_slice(&base[cp_off as usize..end as usize]);
            copy_count += 1;
            instr.push(InstrRange {
                index,
                kind: "copy",
                delta_off: instr_start,
                delta_len: pos - instr_start,
                copy_off: cp_off as u64,
                copy_size: cp_size as u64,
            });
        } else if opcode != 0 {
            let len = opcode as usize;
            if pos + len > delta.len() {
                return Err(DeltaError::Truncated("insert literal bytes".into()));
            }
            if out.len() + len > result_declared as usize {
                return Err(DeltaError::OutputExceedsDeclared);
            }
            out.extend_from_slice(&delta[pos..pos + len]);
            pos += len;
            insert_count += 1;
            instr.push(InstrRange {
                index,
                kind: "insert",
                delta_off: instr_start,
                delta_len: pos - instr_start,
                copy_off: 0,
                copy_size: len as u64,
            });
        } else {
            return Err(DeltaError::InvalidZeroOpcode);
        }
        index += 1;
    }

    if out.len() as u64 != result_declared {
        return Err(DeltaError::ResultSizeMismatch {
            declared: result_declared,
            actual: out.len() as u64,
        });
    }

    Ok(AppliedDelta {
        result: out,
        base_size_declared: base_declared,
        result_size_declared: result_declared,
        copy_count,
        insert_count,
        instr,
    })
}

/// Encode a trivial "whole result is one insert" delta. Useful for tests/builders.
pub fn encode_insert_delta(base_len: u64, result: &[u8]) -> Vec<u8> {
    use crate::git::varint::write_size_encoding;
    let mut d = Vec::new();
    write_size_encoding(base_len, 0, &mut d);
    write_size_encoding(result.len() as u64, 0, &mut d);
    let mut pos = 0usize;
    while pos < result.len() {
        let chunk = result.len() - pos;
        let take = chunk.min(127);
        d.push(take as u8);
        d.extend_from_slice(&result[pos..pos + take]);
        pos += take;
    }
    d
}

/// Encode a single-command COPY delta producing `base[start..start+len]`.
pub fn encode_copy_delta(base_len: u64, start: usize, len: usize) -> Vec<u8> {
    use crate::git::varint::write_size_encoding;
    let mut d = Vec::new();
    write_size_encoding(base_len, 0, &mut d);
    write_size_encoding(len as u64, 0, &mut d);

    let mut opcode = 0x80u8;
    let mut off_bytes = Vec::new();
    let mut off = start as u32;
    for byte_idx in 0..4 {
        let byte = (off & 0xff) as u8;
        off >>= 8;
        if byte != 0 {
            opcode |= 1 << byte_idx;
            off_bytes.push(byte);
        }
    }
    let mut size_bytes = Vec::new();
    // A zero size field means 0x10000.
    let size = if len == 0x10000 { 0 } else { len as u32 };
    let mut rem = size;
    for byte_idx in 0..3 {
        let byte = (rem & 0xff) as u8;
        rem >>= 8;
        if byte != 0 {
            opcode |= 1 << (4 + byte_idx);
            size_bytes.push(byte);
        }
    }
    d.push(opcode);
    d.extend_from_slice(&off_bytes);
    d.extend_from_slice(&size_bytes);
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_roundtrip() {
        let base = b"base contents";
        let want = b"completely new result text";
        let d = encode_insert_delta(base.len() as u64, want);
        let a = apply_delta(base, &d).unwrap();
        assert_eq!(a.result, want);
        assert_eq!(a.insert_count, 1);
    }

    #[test]
    fn copy_roundtrip() {
        let base = b"0123456789ABCDEF";
        let d = encode_copy_delta(base.len() as u64, 2, 6);
        let a = apply_delta(base, &d).unwrap();
        assert_eq!(a.result, b"234567");
        assert_eq!(a.copy_count, 1);
    }

    #[test]
    fn copy_out_of_range() {
        // base size 4, copy offset 2 size 10
        let d = vec![
            4, 10, // sizes
            0x80 | 0x01, 0x02, // offset=2, size defaults 0x10000
        ];
        let err = apply_delta(b"abcd", &d).unwrap_err();
        assert!(matches!(err, DeltaError::CopyOutOfRange { .. }));
    }

    #[test]
    fn zero_opcode_invalid() {
        let d = vec![0, 0, 0];
        assert_eq!(
            apply_delta(b"", &d).unwrap_err(),
            DeltaError::InvalidZeroOpcode
        );
    }

    #[test]
    fn base_size_mismatch() {
        let d = vec![9, 0];
        assert!(matches!(
            apply_delta(b"abc", &d).unwrap_err(),
            DeltaError::BaseSizeMismatch { .. }
        ));
    }
}
