#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstrKind {
    Copy { off: u64, size: u64 },
    Insert { len: u64 },
}

#[derive(Debug, Clone)]
pub struct DeltaInstr {
    pub start: usize,
    pub end: usize,
    pub kind: InstrKind,
}

#[derive(Debug)]
pub struct DeltaOutcome {
    pub out: Vec<u8>,
    pub instrs: Vec<DeltaInstr>,
    pub src_size: u64,
    pub dst_size: u64,
    pub header_len: usize,
}

fn read_varint(bytes: &[u8], mut pos: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        let c = *bytes.get(pos)?;
        pos += 1;
        value |= ((c & 0x7f) as u64) << shift;
        if c & 0x80 == 0 {
            return Some((value, pos));
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
}

pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<DeltaOutcome, String> {
    let (src_size, p1) = read_varint(delta, 0).ok_or("delta: 源大小 varint 损坏")?;
    if src_size != base.len() as u64 {
        return Err(format!(
            "delta 源大小不符: 指令要求 {src_size}, 实际 base 为 {}",
            base.len()
        ));
    }
    let (dst_size, p2) = read_varint(delta, p1).ok_or("delta: 目标大小 varint 损坏")?;
    let mut pos = p2;
    let mut out = Vec::with_capacity(dst_size.min(1 << 26) as usize);
    let mut instrs = Vec::new();
    while pos < delta.len() {
        let start = pos;
        let cmd = delta[pos];
        pos += 1;
        if cmd & 0x80 != 0 {
            let mut off = 0u64;
            let mut size = 0u64;
            for k in 0..4 {
                if cmd & (1 << k) != 0 {
                    let b = *delta.get(pos).ok_or("delta: copy 偏移被截断")? as u64;
                    pos += 1;
                    off |= b << (8 * k);
                }
            }
            for k in 0..3 {
                if cmd & (0x10 << k) != 0 {
                    let b = *delta.get(pos).ok_or("delta: copy 长度被截断")? as u64;
                    pos += 1;
                    size |= b << (8 * k);
                }
            }
            if size == 0 {
                size = 0x10000;
            }
            let end_off = off
                .checked_add(size)
                .ok_or("delta: copy 范围溢出")?;
            if end_off > base.len() as u64 {
                return Err(format!(
                    "delta: copy [{off}..{end_off}) 超出 base 长度 {}",
                    base.len()
                ));
            }
            out.extend_from_slice(&base[off as usize..end_off as usize]);
            instrs.push(DeltaInstr {
                start,
                end: pos,
                kind: InstrKind::Copy { off, size },
            });
        } else if cmd != 0 {
            let n = cmd as usize;
            if pos + n > delta.len() {
                return Err("delta: insert 字面量被截断".into());
            }
            out.extend_from_slice(&delta[pos..pos + n]);
            pos += n;
            instrs.push(DeltaInstr {
                start,
                end: pos,
                kind: InstrKind::Insert { len: n as u64 },
            });
        } else {
            return Err("delta: 保留操作码 0".into());
        }
        if out.len() as u64 > dst_size {
            return Err(format!(
                "delta: 输出超过声明目标大小 {dst_size} (大小欺骗)"
            ));
        }
    }
    if out.len() as u64 != dst_size {
        return Err(format!(
            "delta: 目标大小不符, 声明 {dst_size}, 实际 {}",
            out.len()
        ));
    }
    Ok(DeltaOutcome {
        out,
        instrs,
        src_size,
        dst_size,
        header_len: p2,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::make_delta;

    #[test]
    fn roundtrip_copy_and_insert() {
        let base = b"the quick brown fox jumps over the lazy dog".to_vec();
        let target = b"the quick brown fox jumps over the lazy cat!!".to_vec();
        let delta = make_delta(&base, &target);
        let outcome = apply_delta(&base, &delta).unwrap();
        assert_eq!(outcome.out, target);
        assert!(outcome
            .instrs
            .iter()
            .any(|i| matches!(i.kind, InstrKind::Copy { .. })));
        assert!(outcome
            .instrs
            .iter()
            .any(|i| matches!(i.kind, InstrKind::Insert { .. })));
    }

    #[test]
    fn rejects_wrong_base_size() {
        let delta = make_delta(b"abc", b"abd");
        let err = apply_delta(b"abcd", &delta).unwrap_err();
        assert!(err.contains("源大小不符"));
    }

    #[test]
    fn rejects_copy_out_of_range() {
        let mut delta = vec![3u8, 3u8];
        delta.push(0x80 | 0x01 | 0x10);
        delta.push(10);
        delta.push(3);
        let err = apply_delta(b"abc", &delta).unwrap_err();
        assert!(err.contains("超出 base"));
    }
}
