//! Git delta 指令流（copy / insert）的解析与应用。
//!
//! 指令流布局：
//! ```text
//! base_size   = 小端变长 7bit
//! result_size = 小端变长 7bit
//! 指令序列：
//!   bit7=1            copy：随后最多 7 个字节给出 (offset, size)
//!   0x01..=0x7f       insert：直接追加该数量的字节
//!   0x00              保留，出现即损坏
//! ```

use crate::gitid::read_size_encoding;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsnKind {
    Copy,
    Insert,
}

/// 单条 delta 指令的取证记录。
#[derive(Debug, Clone)]
pub struct InsnRec {
    pub kind: InsnKind,
    /// 指令在 delta 字节流中的范围（起点..终点，含操作码与参数字节；
    /// insert 的范围还包含其数据字节）。
    pub range: (usize, usize),
    /// copy：从 base 读取的偏移与长度；insert：为 None。
    pub copy_src: Option<(usize, usize)>,
    /// insert 内联数据在 delta 中的范围；copy：为 None。
    pub data_range: Option<(usize, usize)>,
    /// 应用该指令后输出流的结束偏移。
    pub out_end: usize,
}

#[derive(Debug, Clone)]
pub struct DeltaHeader {
    pub base_size: u64,
    pub result_size: u64,
    pub header_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeltaError {
    /// delta 头（两个变长长度）损坏。
    BadHeader(String),
    /// 0x00 保留操作码。
    ReservedOpcode(usize),
    /// 指令在流中被截断（参数或内联数据不足）。
    Truncated { at: usize, what: &'static str },
    /// copy 越界：offset+size 超出 base，或 size==0 等非法组合。
    CopyOutOfRange {
        at: usize,
        offset: usize,
        size: usize,
        base_len: usize,
    },
    /// 实际输出长度与 delta 头声明的 result_size 不一致（大小欺骗的一种）。
    ResultSizeMismatch { declared: u64, actual: usize },
    /// 应用结束后仍有多余字节。
    TrailingBytes(usize),
}

#[derive(Debug, Clone)]
pub struct ApplyReport {
    pub header: DeltaHeader,
    pub insns: Vec<InsnRec>,
    pub output: Vec<u8>,
    /// 从 base 读取（copy）的总字节数，即“输入长度”。
    pub copied_bytes: usize,
    /// 内联插入的总字节数。
    pub inserted_bytes: usize,
}

pub fn parse_header(delta: &[u8]) -> Result<DeltaHeader, DeltaError> {
    let mut pos = 0usize;
    let base_size =
        read_size_encoding(delta, &mut pos).map_err(|e| DeltaError::BadHeader(e))?;
    let result_size =
        read_size_encoding(delta, &mut pos).map_err(|e| DeltaError::BadHeader(e))?;
    Ok(DeltaHeader {
        base_size,
        result_size,
        header_len: pos,
    })
}

/// 应用 delta。任何越界/截断/声明不符都返回错误，且不产出“半成品对象”。
pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<ApplyReport, DeltaError> {
    let header = parse_header(delta)?;
    if header.base_size as usize != base.len() {
        return Err(DeltaError::CopyOutOfRange {
            at: 0,
            offset: 0,
            size: 0,
            base_len: base.len(),
        });
    }

    let mut pos = header.header_len;
    let mut out = Vec::with_capacity(header.result_size as usize);
    let mut insns = Vec::new();
    let mut copied_bytes = 0usize;
    let mut inserted_bytes = 0usize;

    while pos < delta.len() {
        let op_at = pos;
        let op = delta[pos];
        pos += 1;

        if op & 0x80 != 0 {
            // copy 指令：低位 bit0..bit3 选择 offset 的字节，bit4..bit6 选择 size 的字节。
            let mut cp_offset: usize = 0;
            let mut cp_size: usize = 0;
            for i in 0..4u32 {
                if op & (1 << i) != 0 {
                    if pos >= delta.len() {
                        return Err(DeltaError::Truncated {
                            at: op_at,
                            what: "copy offset 参数不足",
                        });
                    }
                    cp_offset |= (delta[pos] as usize) << (8 * i);
                    pos += 1;
                }
            }
            for i in 0..3u32 {
                if op & (1 << (4 + i)) != 0 {
                    if pos >= delta.len() {
                        return Err(DeltaError::Truncated {
                            at: op_at,
                            what: "copy size 参数不足",
                        });
                    }
                    cp_size |= (delta[pos] as usize) << (8 * i);
                    pos += 1;
                }
            }
            if cp_size == 0 {
                cp_size = 0x10000; // Git 规定 size 字段全 0 时表示 65536
            }
            let end = match cp_offset.checked_add(cp_size) {
                Some(e) if e <= base.len() => e,
                _ => {
                    return Err(DeltaError::CopyOutOfRange {
                        at: op_at,
                        offset: cp_offset,
                        size: cp_size,
                        base_len: base.len(),
                    })
                }
            };
            out.extend_from_slice(&base[cp_offset..end]);
            copied_bytes += cp_size;
            insns.push(InsnRec {
                kind: InsnKind::Copy,
                range: (op_at, pos),
                copy_src: Some((cp_offset, cp_size)),
                data_range: None,
                out_end: out.len(),
            });
        } else if op == 0 {
            return Err(DeltaError::ReservedOpcode(op_at));
        } else {
            let take = op as usize;
            if pos + take > delta.len() {
                return Err(DeltaError::Truncated {
                    at: op_at,
                    what: "insert 内联数据不足",
                });
            }
            out.extend_from_slice(&delta[pos..pos + take]);
            inserted_bytes += take;
            insns.push(InsnRec {
                kind: InsnKind::Insert,
                range: (op_at, pos + take),
                copy_src: None,
                data_range: Some((pos, pos + take)),
                out_end: out.len(),
            });
            pos += take;
        }
    }

    if out.len() as u64 != header.result_size {
        return Err(DeltaError::ResultSizeMismatch {
            declared: header.result_size,
            actual: out.len(),
        });
    }

    Ok(ApplyReport {
        header,
        insns,
        output: out,
        copied_bytes,
        inserted_bytes,
    })
}

/// 构造一条 delta 指令流（供自建测试包使用，避免依赖系统 git）。
pub fn build_delta(base: &[u8], result: &[u8]) -> Vec<u8> {
    use crate::gitid::write_size_encoding;
    let mut delta = Vec::new();
    write_size_encoding(base.len() as u64, 0, &mut delta);
    write_size_encoding(result.len() as u64, 0, &mut delta);

    // 简单的贪心：能 copy 就 copy（4 字节以上），否则 insert。
    let mut i = 0usize;
    while i < result.len() {
        let mut best: Option<(usize, usize)> = None;
        if i + 4 <= result.len() {
            for off in 0..base.len() {
                let mut n = 0usize;
                while i + n < result.len()
                    && off + n < base.len()
                    && result[i + n] == base[off + n]
                {
                    n += 1;
                }
                if n >= 4 && best.map(|(_, l)| n > l).unwrap_or(true) {
                    best = Some((off, n));
                }
            }
        }
        if let Some((off, n)) = best {
            let mut op = 0x80u8;
            let mut ob = [0u8; 4];
            let mut on = 0;
            let mut v = off;
            for k in 0..4 {
                if v & 0xff != 0 || (v != 0 && k < 4) {
                    ob[on] = (v & 0xff) as u8;
                    op |= 1 << k;
                    on += 1;
                }
                v >>= 8;
                if v == 0 {
                    break;
                }
            }
            let mut sb = [0u8; 3];
            let mut sn = 0;
            let size = if n == 0x10000 { 0 } else { n };
            let mut sv = size;
            for k in 0..3 {
                if sv & 0xff != 0 {
                    sb[sn] = (sv & 0xff) as u8;
                    op |= 1 << (4 + k);
                    sn += 1;
                }
                sv >>= 8;
                if sv == 0 {
                    break;
                }
            }
            delta.push(op);
            delta.extend_from_slice(&ob[..on]);
            delta.extend_from_slice(&sb[..sn]);
            i += n;
        } else {
            let take = (result.len() - i).min(127);
            delta.push(take as u8);
            delta.extend_from_slice(&result[i..i + take]);
            i += take;
        }
    }
    delta
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_simple_insert_and_copy() {
        let base = b"hello world";
        let result = b"hello brave new world";
        let d = build_delta(base, result);
        let r = apply_delta(base, &d).unwrap();
        assert_eq!(r.output, result);
        assert!(r.copied_bytes > 0);
    }

    #[test]
    fn size_spoof_in_result_header_is_rejected() {
        let base = b"abc";
        let mut d = Vec::new();
        use crate::gitid::write_size_encoding;
        write_size_encoding(3, 0, &mut d);
        write_size_encoding(99, 0, &mut d); // 谎称输出 99 字节
        d.push(3);
        d.extend_from_slice(b"abc");
        assert_eq!(
            apply_delta(base, &d),
            Err(DeltaError::ResultSizeMismatch {
                declared: 99,
                actual: 3
            })
        );
    }

    #[test]
    fn copy_out_of_range_is_rejected() {
        let base = b"abc";
        let mut d = Vec::new();
        use crate::gitid::write_size_encoding;
        write_size_encoding(3, 0, &mut d);
        write_size_encoding(4, 0, &mut d);
        d.push(0x80 | 0x01 | 0x10); // copy offset byte0 + size byte0
        d.push(2); // offset 2
        d.push(4); // size 4 -> 2+4 > 3
        assert!(matches!(
            apply_delta(base, &d),
            Err(DeltaError::CopyOutOfRange { .. })
        ));
    }
}
