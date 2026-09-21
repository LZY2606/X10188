//! Git delta program parsing and application, with per-instruction ranges.

#[derive(Debug, Clone, serde::Serialize)]
pub enum InstrKind {
    Copy { offset: u64, size: u64 },
    Insert { len: u64 },
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DeltaInstr {
    pub pos: usize, // byte offset of the instruction inside the delta data
    pub len: usize, // byte length of the instruction inside the delta data
    pub kind: InstrKind,
}

#[derive(Debug)]
pub struct DeltaApply {
    pub result: Vec<u8>,
    pub instrs: Vec<DeltaInstr>,
    pub instr_start: usize, // offset of first instruction byte in delta data
    pub instr_end: usize,   // end of instruction stream (== delta.len())
    pub base_size: u64,
    pub result_size: u64,
}

fn delta_varint(data: &[u8], pos: usize) -> Result<(u64, usize), String> {
    let mut p = pos;
    let mut v = 0u64;
    let mut shift = 0u32;
    loop {
        let c = *data.get(p).ok_or("truncated delta size varint")?;
        p += 1;
        v |= ((c & 0x7f) as u64) << shift;
        shift += 7;
        if shift > 63 {
            return Err("delta size varint overflow".into());
        }
        if c & 0x80 == 0 {
            break;
        }
    }
    Ok((v, p))
}

pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<DeltaApply, String> {
    let (base_size, p1) = delta_varint(delta, 0)?;
    let (result_size, p2) = delta_varint(delta, p1)?;
    if base_size != base.len() as u64 {
        return Err(format!(
            "base size mismatch: delta expects {}, base is {}",
            base_size,
            base.len()
        ));
    }
    if result_size > crate::pack::HARD_CAP {
        return Err(format!("delta result size {} exceeds hard cap", result_size));
    }
    let instr_start = p2;
    let mut out: Vec<u8> = Vec::with_capacity(result_size as usize);
    let mut instrs = Vec::new();
    let mut p = p2;
    while p < delta.len() {
        let ipos = p;
        let cmd = delta[p];
        p += 1;
        if cmd & 0x80 != 0 {
            let mut off = 0u64;
            let mut size = 0u64;
            for i in 0..4 {
                if cmd & (1 << i) != 0 {
                    let b = *data_get(delta, p)?;
                    p += 1;
                    off |= (b as u64) << (8 * i);
                }
            }
            for i in 0..3 {
                if cmd & (0x10 << i) != 0 {
                    let b = *data_get(delta, p)?;
                    p += 1;
                    size |= (b as u64) << (8 * i);
                }
            }
            if size == 0 {
                size = 0x10000;
            }
            if off.checked_add(size).map_or(true, |e| e > base.len() as u64) {
                return Err(format!(
                    "copy instruction out of base bounds: off={} size={} base={}",
                    off,
                    size,
                    base.len()
                ));
            }
            out.extend_from_slice(&base[off as usize..(off + size) as usize]);
            instrs.push(DeltaInstr {
                pos: ipos,
                len: p - ipos,
                kind: InstrKind::Copy { offset: off, size },
            });
        } else if cmd != 0 {
            let n = cmd as usize;
            if p + n > delta.len() {
                return Err("insert instruction overruns delta data".into());
            }
            out.extend_from_slice(&delta[p..p + n]);
            p += n;
            instrs.push(DeltaInstr {
                pos: ipos,
                len: n + 1,
                kind: InstrKind::Insert { len: n as u64 },
            });
        } else {
            return Err("reserved delta opcode 0".into());
        }
        if out.len() as u64 > result_size {
            return Err(format!(
                "delta output exceeds declared result size {}",
                result_size
            ));
        }
    }
    if out.len() as u64 != result_size {
        return Err(format!(
            "result size mismatch: declared {}, produced {}",
            result_size,
            out.len()
        ));
    }
    Ok(DeltaApply {
        result: out,
        instrs,
        instr_start,
        instr_end: delta.len(),
        base_size,
        result_size,
    })
}

fn data_get(data: &[u8], p: usize) -> Result<&u8, String> {
    data.get(p).ok_or_else(|| "truncated copy instruction".to_string())
}
