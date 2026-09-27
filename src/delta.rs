//! Git delta 指令解析与应用。
//!
//! 记录每个指令的指令字节范围、拷贝参数、输入/输出长度与校验结果，
//! 严格执行 Git 的边界约束（不允许读越界、写超范围、空拷贝等）。

use crate::git;

/// 单条 delta 指令的取证记录。
#[derive(Debug, Clone)]
pub struct HopInstr {
    pub kind: String,
    /// 在 delta 指令段内的字节起止（相对于指令段起始）。
    pub range_start: usize,
    pub range_end: usize,
    pub src_offset: u64,
    pub copy_size: u64,
    pub literal_len: usize,
}

/// 一次 delta 应用的完整结果。
#[derive(Debug, Clone)]
pub struct AppliedDelta {
    pub expected_src_size: u64,
    pub expected_dst_size: u64,
    pub actual_src_size: usize,
    pub actual_dst_size: usize,
    pub instrs: Vec<HopInstr>,
    pub output: Vec<u8>,
    /// 尺寸/边界全部合法。
    pub valid: bool,
    pub error: Option<String>,
}

fn read_size(delta: &[u8], pos: &mut usize) -> Result<u64, String> {
    let mut size = 0u64;
    let mut shift = 0u32;
    loop {
        if *pos >= delta.len() {
            return Err("delta: 尺寸编码被截断".into());
        }
        let c = delta[*pos];
        *pos += 1;
        size |= u64::from(c & 0x7f) << shift;
        shift += 7;
        if c & 0x80 == 0 {
            break;
        }
        if shift > 63 {
            return Err("delta: 尺寸编码过长".into());
        }
    }
    Ok(size)
}

/// 解析并应用 delta。`base` 为 base 对象的最终内容。
pub fn apply_delta(base: &[u8], delta: &[u8]) -> AppliedDelta {
    let mut result = AppliedDelta {
        expected_src_size: 0,
        expected_dst_size: 0,
        actual_src_size: base.len(),
        actual_dst_size: 0,
        instrs: Vec::new(),
        output: Vec::new(),
        valid: false,
        error: None,
    };

    let parse = (|| -> Result<(), String> {
        let mut pos = 0usize;
        let src_size = read_size(delta, &mut pos)?;
        let dst_size = read_size(delta, &mut pos)?;
        result.expected_src_size = src_size;
        result.expected_dst_size = dst_size;

        if src_size != base.len() as u64 {
            return Err(format!(
                "delta: 源尺寸不匹配（声明 {}，实际 {}）",
                src_size,
                base.len()
            ));
        }
        // 防御：按声明尺寸预分配有上限，避免伪造大尺寸直接 OOM。
        if dst_size > 256 * 1024 * 1024 {
            return Err("delta: 目标尺寸超过 256MiB 安全上限".into());
        }
        result.output = Vec::with_capacity(dst_size.min(1 << 20) as usize);

        while pos < delta.len() {
            let op = delta[pos];
            let instr_start = pos;
            pos += 1;
            if op & 0x80 != 0 {
                // copy from source
                let mut offset = 0u64;
                let mut size = 0u64;
                for i in 0..4u32 {
                    if op & (1 << i) != 0 {
                        if pos >= delta.len() {
                            return Err("delta: copy 偏移被截断".into());
                        }
                        offset |= u64::from(delta[pos]) << (8 * i);
                        pos += 1;
                    }
                }
                for i in 0..3u32 {
                    if op & (1 << (4 + i)) != 0 {
                        if pos >= delta.len() {
                            return Err("delta: copy 长度被截断".into());
                        }
                        size |= u64::from(delta[pos]) << (8 * i);
                        pos += 1;
                    }
                }
                if size == 0 {
                    size = 0x10000;
                }
                let end = offset.checked_add(size).ok_or("delta: copy 范围溢出")?;
                if end > base.len() as u64 {
                    return Err(format!(
                        "delta: copy 越界 [{}+{}={}) 但 base 长度 {}",
                        offset,
                        size,
                        end,
                        base.len()
                    ));
                }
                result.output.extend_from_slice(
                    &base[offset as usize..(offset + size) as usize],
                );
                result.instrs.push(HopInstr {
                    kind: "copy".into(),
                    range_start: instr_start,
                    range_end: pos,
                    src_offset: offset,
                    copy_size: size,
                    literal_len: 0,
                });
            } else if op != 0 {
                // insert literal
                let len = op as usize;
                if pos + len > delta.len() {
                    return Err("delta: 字面量被截断".into());
                }
                result.output.extend_from_slice(&delta[pos..pos + len]);
                pos += len;
                result.instrs.push(HopInstr {
                    kind: "insert".into(),
                    range_start: instr_start,
                    range_end: pos,
                    src_offset: 0,
                    copy_size: 0,
                    literal_len: len,
                });
            } else {
                return Err("delta: 遇到保留指令 0x00".into());
            }
        }

        if result.output.len() as u64 != dst_size {
            return Err(format!(
                "delta: 输出尺寸不匹配（声明 {}，实际 {}）",
                dst_size,
                result.output.len()
            ));
        }
        Ok(())
    })();

    result.actual_dst_size = result.output.len();
    match parse {
        Ok(()) => {
            result.valid = true;
        }
        Err(e) => {
            result.valid = false;
            result.error = Some(e);
        }
    }
    result
}

/// 用 type_code + 内容重算 git object id。
pub fn recalc_id(type_code: u8, content: &[u8]) -> Result<[u8; 20], String> {
    git::object_id(type_code, content)
}

/// 构造 delta：以“整体从 base 拷贝 + 末尾追加”的形式生成最简 delta，
/// 供测试构造 pack 使用。
pub fn build_append_delta(base: &[u8], extra: &[u8]) -> Vec<u8> {
    fn enc_size(mut size: u64) -> Vec<u8> {
        let mut out = Vec::new();
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
        out
    }
    let mut delta = enc_size(base.len() as u64);
    delta.extend_from_slice(&enc_size((base.len() + extra.len()) as u64));
    if !base.is_empty() {
        let mut op = 0x80u8;
        // offset 0：不写任何偏移字节即可（全 0）
        let size = base.len() as u64;
        if size != 0x10000 {
            for i in 0..3u32 {
                let byte = ((size >> (8 * i)) & 0xff) as u8;
                if byte != 0 {
                    op |= 1 << (4 + i);
                }
            }
        }
        delta.push(op);
        for i in 0..3u32 {
            let byte = ((size >> (8 * i)) & 0xff) as u8;
            if byte != 0 && size != 0x10000 {
                delta.push(byte);
            }
        }
    }
    if !extra.is_empty() {
        assert!(extra.len() < 128);
        delta.push(extra.len() as u8);
        delta.extend_from_slice(extra);
    }
    delta
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_delta_roundtrip() {
        let base = b"hello base content!!";
        let extra = b" + delta tail";
        let delta = build_append_delta(base, extra);
        let applied = apply_delta(base, &delta);
        assert!(applied.valid, "{:?}", applied.error);
        let mut expected = base.to_vec();
        expected.extend_from_slice(extra);
        assert_eq!(applied.output, expected);
    }

    #[test]
    fn rejects_copy_overrun() {
        // 手工构造：src=4, dst=8, copy offset=2 size=4 => 越界
        let delta = [4u8, 8, 0x80 | 0x01, 2]; // copy off=2, size 默认 0x10000 越界
        let applied = apply_delta(b"abcd", &delta);
        assert!(!applied.valid);
    }
}
