//! Git delta format application with full per-step provenance.
//!
//! Delta = varint(base_size) varint(result_size) (copy | insert)+
//!   copy:   top bit set; bitmask selects offset/size bytes (1-based)
//!   insert: top bit clear; count = opcode & 0x7f (1..=127)

use crate::git::decode_size;

#[derive(Debug, Clone)]
pub enum DeltaOp {
    Copy {
        offset: usize,
        size: usize,
    },
    Insert {
        data: Vec<u8>,
    },
}

#[derive(Debug, Clone)]
pub struct DeltaInstruction {
    pub index: usize,
    pub kind: &'static str,
    /// Byte range of this instruction inside the delta blob.
    pub delta_start: usize,
    pub delta_end: usize,
    pub offset: Option<usize>,
    pub size: usize,
    /// Input cursor position in the *base* that this instruction consumes from
    /// (copy start); for inserts this is the base cursor (unchanged).
    pub input_pos: usize,
    /// Output length after applying this instruction.
    pub output_len_after: usize,
    pub check: Result<(), String>,
}

#[derive(Debug)]
pub struct AppliedDelta {
    pub base_size_declared: u64,
    pub result_size_declared: u64,
    pub output: Vec<u8>,
    pub ops: Vec<DeltaInstruction>,
}

pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<AppliedDelta, String> {
    let (base_size, n1) = decode_size(delta).ok_or("delta: missing base size")?;
    let (result_size, n2) =
        decode_size(&delta[n1..]).ok_or("delta: missing result size")?;
    let header_len = n1 + n2;
    if base_size as usize != base.len() {
        return Err(format!(
            "delta base size mismatch: delta declares {base_size}, base is {} bytes",
            base.len()
        ));
    }
    // Protect the allocation against a spoofed, impossibly large result size.
    if result_size > 256 * 1024 * 1024 {
        return Err(format!("delta result size {result_size} exceeds safety cap"));
    }

    let mut out = Vec::with_capacity(result_size.min(64 * 1024 * 1024) as usize);
    let mut pos = header_len;
    let mut input_pos = 0usize;
    let mut ops = Vec::new();
    let mut index = 0usize;

    while pos < delta.len() {
        let op_start = pos;
        let opcode = delta[pos];
        pos += 1;
        if opcode == 0 {
            return Err(format!("delta opcode 0 is reserved (at {op_start})"));
        }
        if opcode & 0x80 != 0 {
            let mut offset = 0usize;
            let mut size = 0usize;
            for shift_i in 0..4 {
                if opcode & (1 << shift_i) != 0 {
                    if pos >= delta.len() {
                        return Err("copy instruction truncated (offset bytes)".into());
                    }
                    offset |= (delta[pos] as usize) << (shift_i * 8);
                    pos += 1;
                }
            }
            for shift_i in 0..3 {
                if opcode & (1 << (4 + shift_i)) != 0 {
                    if pos >= delta.len() {
                        return Err("copy instruction truncated (size bytes)".into());
                    }
                    size |= (delta[pos] as usize) << (shift_i * 8);
                    pos += 1;
                }
            }
            if size == 0 {
                size = 0x10000;
            }
            let check = if offset.checked_add(size).map_or(true, |end| end > base.len()) {
                Err(format!(
                    "copy out of base bounds: offset={offset} size={size} base_len={}",
                    base.len()
                ))
            } else {
                out.extend_from_slice(&base[offset..offset + size]);
                input_pos = offset + size;
                Ok(())
            };
            let output_len_after = out.len();
            ops.push(DeltaInstruction {
                index,
                kind: "copy",
                delta_start: op_start,
                delta_end: pos,
                offset: Some(offset),
                size,
                input_pos,
                output_len_after,
                check,
            });
            index += 1;
        } else {
            let count = (opcode & 0x7f) as usize;
            if pos + count > delta.len() {
                return Err(format!(
                    "insert of {count} bytes overruns delta blob at {op_start}"
                ));
            }
            let data = delta[pos..pos + count].to_vec();
            pos += count;
            out.extend_from_slice(&data);
            ops.push(DeltaInstruction {
                index,
                kind: "insert",
                delta_start: op_start,
                delta_end: pos,
                offset: None,
                size: count,
                input_pos,
                output_len_after: out.len(),
                check: Ok(()),
            });
            index += 1;
        }
    }

    if out.len() as u64 != result_size {
        return Err(format!(
            "size spoof: delta declares result {result_size} but instructions produced {} bytes",
            out.len()
        ));
    }
    Ok(AppliedDelta {
        base_size_declared: base_size,
        result_size_declared: result_size,
        output: out,
        ops,
    })
}

/// Build a trivial delta that reproduces `target` from a compatible base.
/// Used by the synthetic fixtures: emits one copy covering the shared prefix
/// and one insert for the remainder (good enough to form real chains).
pub fn delta_from_copy_insert(base: &[u8], target: &[u8]) -> Vec<u8> {
    let common = base
        .iter()
        .zip(target.iter())
        .take_while(|(a, b)| a == b)
        .count();
    let mut d = Vec::new();
    d.extend(crate::git::encode_size(base.len() as u64));
    d.extend(crate::git::encode_size(target.len() as u64));
    if common > 0 {
        // copy opcode with offset 0 (size encoded because it's not 0x10000)
        d.push(0x80 | 0x01 | 0x10); // offset byte0 + size byte0
        d.push(0u8); // offset = 0
        d.push(common as u8); // size
    }
    let rest = &target[common..];
    let mut i = 0;
    while i < rest.len() {
        let n = rest.len().min(127);
        d.push(n as u8);
        d.extend_from_slice(&rest[i..i + n]);
        i += n;
        if i >= rest.len() {
            break;
        }
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_insert_roundtrip() {
        let base = b"hello world, this is git";
        let target = b"hello world, this is GIT!!";
        let d = delta_from_copy_insert(base, target);
        let a = apply_delta(base, &d).unwrap();
        assert_eq!(a.output, target);
    }

    #[test]
    fn rejects_bad_base_size() {
        let mut d = crate::git::encode_size(99);
        d.extend(crate::git::encode_size(0));
        let e = apply_delta(b"abc", &d).unwrap_err();
        assert!(e.contains("base size mismatch"));
    }

    #[test]
    fn rejects_copy_out_of_bounds() {
        let mut d = crate::git::encode_size(3);
        d.extend(crate::git::encode_size(5));
        d.push(0x80 | 0x01 | 0x10);
        d.push(2); // offset 2
        d.push(10); // size 10 -> beyond base
        let e = apply_delta(b"abc", &d).unwrap_err();
        assert!(e.contains("instructions produced") || e.contains("out of base"));
    }
}
