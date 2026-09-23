use crate::gitobj::parse_varint;

#[derive(Debug, Clone)]
pub enum InstrKind {
    Copy { src_off: usize, src_len: usize },
    Insert,
}

#[derive(Debug, Clone)]
pub struct Instr {
    pub off: usize,       // 指令在 delta 内的偏移
    pub len: usize,       // 指令字节长度
    pub kind: InstrKind,  // copy / insert
    pub out_start: usize, // 写入输出的起点
    pub out_len: usize,   // 写入输出的长度
}

#[derive(Debug)]
pub struct DeltaResult {
    pub out: Vec<u8>,
    pub instrs: Vec<Instr>,
    pub src_size: u64,
    pub tgt_size: u64,
    pub instr_region: (usize, usize), // 指令区在 delta 内的范围
}

pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<DeltaResult, String> {
    let (src_size, n1) = parse_varint(delta, 0)?;
    let (tgt_size, n2) = parse_varint(delta, n1)?;
    if src_size as usize != base.len() {
        return Err(format!(
            "delta 源大小不符: 声明 {} 实际 {}",
            src_size,
            base.len()
        ));
    }
    let mut out = Vec::with_capacity(tgt_size as usize);
    let mut instrs = Vec::new();
    let mut i = n1 + n2;
    let instr_start = i;
    while i < delta.len() {
        let op_off = i;
        let cmd = delta[i];
        i += 1;
        if cmd & 0x80 != 0 {
            let mut cp_off: usize = 0;
            let mut cp_size: usize = 0;
            for bit in 0..4 {
                if cmd & (1 << bit) != 0 {
                    cp_off |= (*delta.get(i).ok_or("copy 指令截断")? as usize) << (8 * bit);
                    i += 1;
                }
            }
            for bit in 0..3 {
                if cmd & (0x10 << bit) != 0 {
                    cp_size |= (*delta.get(i).ok_or("copy 指令截断")? as usize) << (8 * bit);
                    i += 1;
                }
            }
            if cp_size == 0 {
                cp_size = 0x10000;
            }
            if cp_off.checked_add(cp_size).map_or(true, |end| end > base.len()) {
                return Err(format!(
                    "copy 越界: {}..{} 超出 base 长度 {}",
                    cp_off,
                    cp_off + cp_size,
                    base.len()
                ));
            }
            let out_start = out.len();
            out.extend_from_slice(&base[cp_off..cp_off + cp_size]);
            instrs.push(Instr {
                off: op_off,
                len: i - op_off,
                kind: InstrKind::Copy { src_off: cp_off, src_len: cp_size },
                out_start,
                out_len: cp_size,
            });
        } else if cmd != 0 {
            let n = cmd as usize;
            if i + n > delta.len() {
                return Err("insert 指令截断".into());
            }
            let out_start = out.len();
            out.extend_from_slice(&delta[i..i + n]);
            i += n;
            instrs.push(Instr {
                off: op_off,
                len: 1 + n,
                kind: InstrKind::Insert,
                out_start,
                out_len: n,
            });
        } else {
            return Err("非法 delta 指令 0x00".into());
        }
    }
    if out.len() as u64 != tgt_size {
        return Err(format!(
            "delta 目标大小欺骗: 声明 {} 实际 {}",
            tgt_size,
            out.len()
        ));
    }
    Ok(DeltaResult {
        out,
        instrs,
        src_size,
        tgt_size,
        instr_region: (instr_start, delta.len()),
    })
}
