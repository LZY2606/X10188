#[derive(Debug, Clone)]
pub struct DeltaHeader {
    pub src_size: u64,
    pub tgt_size: u64,
    /// 指令区起点（相对 delta 数据开头）
    pub instr_start: usize,
}

fn read_varint(d: &[u8], mut p: usize) -> Result<(u64, usize), String> {
    let mut v: u64 = 0;
    let mut shift = 0;
    loop {
        if p >= d.len() {
            return Err("delta 头部 varint 被截断".into());
        }
        let c = d[p];
        p += 1;
        v |= ((c & 0x7f) as u64) << shift;
        shift += 7;
        if shift > 63 {
            return Err("delta 头部 varint 溢出".into());
        }
        if c & 0x80 == 0 {
            break;
        }
    }
    Ok((v, p))
}

pub fn parse_header(delta: &[u8]) -> Result<DeltaHeader, String> {
    let (src_size, p1) = read_varint(delta, 0)?;
    let (tgt_size, p2) = read_varint(delta, p1)?;
    Ok(DeltaHeader {
        src_size,
        tgt_size,
        instr_start: p2,
    })
}

/// 可重试的中间状态：记录指令游标与已展开的部分输出。
/// 处于该状态的对象绝不能被当作完整对象。
#[derive(Debug, Clone, Default)]
pub struct DeltaCursor {
    pub pos: usize,
    pub out: Vec<u8>,
}

pub enum DeltaOutcome {
    Done(Vec<u8>),
    Paused(DeltaCursor, String),
}

pub struct DeltaLimits {
    /// 单对象展开比例上限（输出/输入）
    pub max_ratio: f64,
    /// 本次运行剩余可展开字节数
    pub byte_budget: u64,
}

/// 应用 delta。预算耗尽时返回 Paused(cursor)，之后可用同一 cursor 继续。
pub fn apply_delta(
    base: &[u8],
    delta: &[u8],
    hdr: &DeltaHeader,
    cursor: DeltaCursor,
    limits: &mut DeltaLimits,
) -> Result<DeltaOutcome, String> {
    if hdr.src_size != base.len() as u64 {
        return Err(format!(
            "delta 源大小 {} 与 base 实际长度 {} 不符",
            hdr.src_size,
            base.len()
        ));
    }
    let mut pos = if cursor.pos == 0 {
        hdr.instr_start
    } else {
        cursor.pos
    };
    let mut out = cursor.out;
    let ratio_cap = |out_len: usize, extra: u64, base_len: usize| -> bool {
        if base_len == 0 {
            return false;
        }
        (out_len as u64 + extra) as f64 > limits_max_ratio_guard(limits.max_ratio) * base_len as f64
    };
    while pos < delta.len() {
        let ip = pos;
        let cmd = delta[pos];
        pos += 1;
        if cmd & 0x80 != 0 {
            let mut cp_off: u64 = 0;
            let mut cp_size: u64 = 0;
            for i in 0..4 {
                if cmd & (1 << i) != 0 {
                    if pos >= delta.len() {
                        return Err("copy 指令被截断".into());
                    }
                    cp_off |= (delta[pos] as u64) << (8 * i);
                    pos += 1;
                }
            }
            for i in 0..3 {
                if cmd & (0x10 << i) != 0 {
                    if pos >= delta.len() {
                        return Err("copy 指令被截断".into());
                    }
                    cp_size |= (delta[pos] as u64) << (8 * i);
                    pos += 1;
                }
            }
            if cp_size == 0 {
                cp_size = 0x10000;
            }
            if cp_off.checked_add(cp_size).map_or(true, |e| e > base.len() as u64) {
                return Err(format!(
                    "copy 指令越界: offset {} size {}，base 长度 {}",
                    cp_off,
                    cp_size,
                    base.len()
                ));
            }
            if ratio_cap(out.len(), cp_size, base.len()) {
                return Ok(DeltaOutcome::Paused(
                    DeltaCursor { pos: ip, out },
                    "单对象展开比例超限".into(),
                ));
            }
            if cp_size > limits.byte_budget {
                return Ok(DeltaOutcome::Paused(
                    DeltaCursor { pos: ip, out },
                    "总展开字节预算耗尽".into(),
                ));
            }
            limits.byte_budget -= cp_size;
            out.extend_from_slice(&base[cp_off as usize..(cp_off + cp_size) as usize]);
        } else if cmd != 0 {
            let n = cmd as usize;
            if pos + n > delta.len() {
                return Err("insert 指令被截断".into());
            }
            if ratio_cap(out.len(), n as u64, base.len()) {
                return Ok(DeltaOutcome::Paused(
                    DeltaCursor { pos: ip, out },
                    "单对象展开比例超限".into(),
                ));
            }
            if n as u64 > limits.byte_budget {
                return Ok(DeltaOutcome::Paused(
                    DeltaCursor { pos: ip, out },
                    "总展开字节预算耗尽".into(),
                ));
            }
            limits.byte_budget -= n as u64;
            out.extend_from_slice(&delta[pos..pos + n]);
            pos += n;
        } else {
            return Err("非法的 0 指令字节".into());
        }
    }
    if out.len() as u64 != hdr.tgt_size {
        return Err(format!(
            "delta 目标大小欺骗: 头部声明 {} 字节，实际展开 {} 字节",
            hdr.tgt_size,
            out.len()
        ));
    }
    Ok(DeltaOutcome::Done(out))
}

fn limits_max_ratio_guard(r: f64) -> f64 {
    if r.is_finite() && r > 0.0 {
        r
    } else {
        f64::MAX
    }
}
