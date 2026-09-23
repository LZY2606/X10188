//! Git delta 指令解析与应用，记录每条指令的范围用于取证展示。

use serde::Serialize;

#[derive(Serialize, Clone, Debug)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Instr {
    Copy { src: u64, len: u64 },
    Insert { off: u64, len: u64 },
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct DeltaMeta {
    pub base_size: u64,
    pub result_size: u64,
    pub instrs: Vec<Instr>,
}

#[derive(Debug)]
pub struct DeltaFailure {
    pub message: String,
    pub meta: DeltaMeta,
}

fn fail<T>(msg: impl Into<String>, meta: DeltaMeta) -> Result<T, DeltaFailure> {
    Err(DeltaFailure { message: msg.into(), meta })
}

fn read_varint(data: &[u8], pos: &mut usize) -> Result<u64, String> {
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        let b = *data.get(*pos).ok_or("delta 头截断")?;
        *pos += 1;
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err("delta varint 过长".into());
        }
    }
    Ok(result)
}

pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<(Vec<u8>, DeltaMeta), DeltaFailure> {
    let mut meta = DeltaMeta::default();
    let mut pos = 0usize;
    meta.base_size = match read_varint(delta, &mut pos) {
        Ok(v) => v,
        Err(e) => return fail(e, meta),
    };
    meta.result_size = match read_varint(delta, &mut pos) {
        Ok(v) => v,
        Err(e) => return fail(e, meta),
    };
    if meta.base_size != base.len() as u64 {
        return fail(
            format!("base 大小不匹配：delta 声明 {}，实际 {}", meta.base_size, base.len()),
            meta,
        );
    }
    let mut out: Vec<u8> = Vec::with_capacity(meta.result_size.min(64 << 20) as usize);
    while pos < delta.len() {
        let cmd = delta[pos];
        pos += 1;
        if cmd & 0x80 != 0 {
            let mut src = 0u64;
            let mut len = 0u64;
            for i in 0..4 {
                if cmd & (1 << i) != 0 {
                    let b = match delta.get(pos) {
                        Some(b) => *b,
                        None => return fail("copy 指令截断", meta),
                    };
                    pos += 1;
                    src |= (b as u64) << (8 * i);
                }
            }
            for i in 0..3 {
                if cmd & (0x10 << i) != 0 {
                    let b = match delta.get(pos) {
                        Some(b) => *b,
                        None => return fail("copy 指令截断", meta),
                    };
                    pos += 1;
                    len |= (b as u64) << (8 * i);
                }
            }
            if len == 0 {
                len = 0x10000;
            }
            if src.saturating_add(len) > base.len() as u64 {
                return fail(
                    format!("copy 越界：src={src} len={len} base 长度={}", base.len()),
                    meta,
                );
            }
            out.extend_from_slice(&base[src as usize..(src + len) as usize]);
            meta.instrs.push(Instr::Copy { src, len });
        } else if cmd != 0 {
            let len = cmd as u64;
            if pos + len as usize > delta.len() {
                return fail("insert 指令越界", meta);
            }
            meta.instrs.push(Instr::Insert { off: pos as u64, len });
            out.extend_from_slice(&delta[pos..pos + len as usize]);
            pos += len as usize;
        } else {
            return fail("遇到保留指令 0", meta);
        }
        if out.len() as u64 > meta.result_size {
            return fail(
                format!("结果超出声明大小 {}（疑似伪造大小）", meta.result_size),
                meta,
            );
        }
    }
    if out.len() as u64 != meta.result_size {
        return fail(
            format!(
                "结果大小与声明不符：声明 {} 实际 {}（疑似伪造大小）",
                meta.result_size,
                out.len()
            ),
            meta,
        );
    }
    Ok((out, meta))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip_via_delta() {
        // base_size=300, result_size=5, insert "hello"
        let mut d = vec![0xAC, 0x02, 0x05, 0x05];
        d.extend_from_slice(b"hello");
        let base = vec![0u8; 300];
        let (out, meta) = apply_delta(&base, &d).unwrap();
        assert_eq!(out, b"hello");
        assert_eq!(meta.base_size, 300);
        assert_eq!(meta.result_size, 5);
    }

    #[test]
    fn fake_result_size_detected() {
        let mut d = vec![0x00, 0x0A, 0x05];
        d.extend_from_slice(b"hello");
        let err = apply_delta(&[], &d).unwrap_err();
        assert!(err.message.contains("大小"));
    }
}
