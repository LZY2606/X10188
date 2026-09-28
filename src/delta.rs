//! Git delta 指令应用，严格校验每一条指令与声明大小。

use crate::encoding::read_delta_size;
use crate::types::DeltaStep;

#[derive(Debug, PartialEq, Eq)]
pub enum DeltaError {
    Truncated,
    BadOpcode(u8),
    BadCopyOperand,
    SizeMismatch { declared: u64, actual: u64 },
    ResultOverflow,
}

/// 应用一层 delta。
///
/// - `delta`：已解压的 delta payload
/// - `base`：base 对象内容
/// - 返回 (result, 指令在 delta 中的累计区间)
pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<(Vec<u8>, Vec<[u64; 2]>), DeltaError> {
    let (base_size, n1) = read_delta_size(delta, 0).ok_or(DeltaError::Truncated)?;
    let (result_size, n2) =
        read_delta_size(delta, n1).ok_or(DeltaError::Truncated)?;
    let header_end = n1 + n2;

    if base_size as usize != base.len() {
        return Err(DeltaError::SizeMismatch {
            declared: base_size,
            actual: base.len() as u64,
        });
    }
    // 防御性：避免按声明值无界预分配。
    if result_size > 1 << 40 {
        return Err(DeltaError::ResultOverflow);
    }

    let mut out = Vec::with_capacity(result_size.min(1 << 20) as usize);
    let mut pos = header_end;
    let mut ranges: Vec<[u64; 2]> = Vec::new();
    let mut range_start = header_end as u64;

    while pos < delta.len() {
        let op = delta[pos];
        if op & 0x80 != 0 {
            // copy from base
            let mut cp_off: u32 = 0;
            let mut cp_size: u32 = 0;
            for bit in 0..3u8 {
                if op & (1 << bit) != 0 {
                    pos += 1;
                    let b = *delta.get(pos).ok_or(DeltaError::Truncated)?;
                    cp_off |= (b as u32) << (8 * bit);
                }
            }
            for bit in 0..3u8 {
                if op & (1 << (4 + bit)) != 0 {
                    pos += 1;
                    let b = *delta.get(pos).ok_or(DeltaError::Truncated)?;
                    cp_size |= (b as u32) << (8 * bit);
                }
            }
            if cp_size == 0 {
                cp_size = 0x10000;
            }
            let end = (cp_off as u64)
                .checked_add(cp_size as u64)
                .ok_or(DeltaError::ResultOverflow)?;
            if end > base.len() as u64 {
                return Err(DeltaError::BadCopyOperand);
            }
            out.extend_from_slice(&base[cp_off as usize..end as usize]);
            pos += 1;
        } else if op > 0 {
            // insert literal
            let n = op as usize;
            if pos + 1 + n > delta.len() {
                return Err(DeltaError::Truncated);
            }
            out.extend_from_slice(&delta[pos + 1..pos + 1 + n]);
            pos += 1 + n;
        } else {
            return Err(DeltaError::BadOpcode(0));
        }
        ranges.push([range_start, pos as u64]);
        range_start = pos as u64;
    }

    if out.len() as u64 != result_size {
        return Err(DeltaError::SizeMismatch {
            declared: result_size,
            actual: out.len() as u64,
        });
    }
    Ok((out, ranges))
}

/// 构造一层 delta（供测试造包）：按 copy/insert 混合生成。
pub fn build_delta(base: &[u8], result: &[u8]) -> Vec<u8> {
    use crate::encoding::write_delta_size;
    let mut d = Vec::new();
    write_delta_size(&mut d, base.len() as u64);
    write_delta_size(&mut d, result.len() as u64);
    // 简化策略：前一半 copy（若可），后一半 insert
    let copy_len = base.len().min(result.len()) / 2;
    if copy_len > 0 {
        let mut op = 0x80u8;
        let off = 0u32;
        let size = copy_len as u32;
        if off & 0xff != 0 { op |= 1; }
        if off & 0xff00 != 0 { op |= 2; }
        if off & 0xff_0000 != 0 { op |= 4; }
        if size & 0xff != 0 { op |= 0x10; }
        if size & 0xff00 != 0 { op |= 0x20; }
        if size & 0xff_0000 != 0 { op |= 0x40; }
        d.push(op);
        for bit in 0..3u8 {
            if op & (1 << bit) != 0 { d.push(((off >> (8 * bit)) & 0xff) as u8); }
        }
        for bit in 0..3u8 {
            if op & (1 << (4 + bit)) != 0 { d.push(((size >> (8 * bit)) & 0xff) as u8); }
        }
    }
    let rest = &result[copy_len..];
    for chunk in rest.chunks(127) {
        d.push(chunk.len() as u8);
        d.extend_from_slice(chunk);
    }
    d
}

/// 生成 DeltaStep 记录。
pub fn step_record(
    index: usize,
    base_desc: String,
    base: &[u8],
    delta: &[u8],
    result: &[u8],
    cmd_ranges: Vec<[u64; 2]>,
    declared: (u64, u64),
    verify_ok: bool,
) -> DeltaStep {
    let _ = (base, delta);
    DeltaStep {
        index,
        base: base_desc,
        cmd_ranges,
        input_len: base.len() as u64,
        output_len: result.len() as u64,
        base_size_declared: declared.0,
        result_size_declared: declared.1,
        verify: if verify_ok { "ok" } else { "sha1-mismatch" }.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delta_roundtrip() {
        let base = b"hello packscope world, this is a git delta test";
        let result = b"hello packscope WORLD, this is a git delta test!!!";
        let d = build_delta(base, result);
        let (out, ranges) = apply_delta(base, &d).unwrap();
        assert_eq!(out, result);
        assert!(!ranges.is_empty());
    }

    #[test]
    fn delta_bad_base_size() {
        let d = build_delta(b"abc", b"axc");
        let err = apply_delta(b"ab", &d).unwrap_err();
        assert!(matches!(err, DeltaError::SizeMismatch { .. }));
    }
}
