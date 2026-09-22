use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Instr {
    pub start: usize,
    pub end: usize,
    pub kind: String,
    pub src_off: u64,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct Budget {
    pub max_depth: u32,
    pub max_total_bytes: u64,
    pub max_ratio: f64,
}

impl Default for Budget {
    fn default() -> Self {
        Budget {
            max_depth: 64,
            max_total_bytes: 64 * 1024 * 1024,
            max_ratio: 100.0,
        }
    }
}

fn varint(d: &[u8], mut i: usize) -> Result<(u64, usize), String> {
    let mut v = 0u64;
    let mut shift = 0;
    loop {
        let b = *d.get(i).ok_or("delta: truncated varint")?;
        i += 1;
        v |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if shift > 63 {
            return Err("delta: varint overflow".into());
        }
        if b & 0x80 == 0 {
            return Ok((v, i));
        }
    }
}

pub fn parse_header(d: &[u8]) -> Result<(u64, u64, usize), String> {
    let (base, n1) = varint(d, 0)?;
    let (target, n2) = varint(d, n1)?;
    Ok((base, target, n2))
}

pub fn parse_instructions(d: &[u8], mut i: usize) -> Result<Vec<Instr>, String> {
    let mut out = Vec::new();
    while i < d.len() {
        let start = i;
        let cmd = d[i];
        i += 1;
        if cmd & 0x80 != 0 {
            let mut off = 0u64;
            let mut size = 0u64;
            for bit in 0..4 {
                if cmd >> bit & 1 == 1 {
                    off |= (*d.get(i).ok_or("delta: truncated copy offset")? as u64) << (8 * bit);
                    i += 1;
                }
            }
            for bit in 0..3 {
                if cmd >> (4 + bit) & 1 == 1 {
                    size |=
                        (*d.get(i).ok_or("delta: truncated copy size")? as u64) << (8 * bit);
                    i += 1;
                }
            }
            if size == 0 {
                size = 0x10000;
            }
            out.push(Instr {
                start,
                end: i,
                kind: "copy".into(),
                src_off: off,
                size,
            });
        } else if cmd != 0 {
            let len = cmd as usize;
            if i + len > d.len() {
                return Err("delta: truncated insert".into());
            }
            i += len;
            out.push(Instr {
                start,
                end: i,
                kind: "insert".into(),
                src_off: 0,
                size: len as u64,
            });
        } else {
            return Err("delta: reserved opcode 0".into());
        }
    }
    Ok(out)
}

pub enum Apply {
    Done(Vec<u8>),
    Paused {
        next_instr: usize,
        partial: Vec<u8>,
        reason: String,
    },
}

pub fn apply(
    base: &[u8],
    program: &[u8],
    skip: usize,
    partial: Vec<u8>,
    expanded: &mut u64,
    budget: &Budget,
) -> Result<Apply, String> {
    let (base_sz, target_sz, hdr) = parse_header(program)?;
    if base_sz as usize != base.len() {
        return Err(format!(
            "delta base size mismatch: program expects {} but base is {} bytes",
            base_sz,
            base.len()
        ));
    }
    let instrs = parse_instructions(program, hdr)?;
    let mut out = partial;
    for (idx, ins) in instrs.iter().enumerate().skip(skip) {
        if ins.kind == "copy" {
            let s = ins.src_off as usize;
            let e = s.saturating_add(ins.size as usize);
            if e > base.len() {
                return Err(format!(
                    "delta copy [{s},{e}) out of base range {} bytes",
                    base.len()
                ));
            }
            out.extend_from_slice(&base[s..e]);
        } else {
            out.extend_from_slice(&program[ins.start + 1..ins.end]);
        }
        *expanded += ins.size;
        if *expanded > budget.max_total_bytes {
            return Ok(Apply::Paused {
                next_instr: idx + 1,
                partial: out,
                reason: "total expanded bytes budget exceeded".into(),
            });
        }
        if budget.max_ratio > 0.0 && (out.len() as f64) > (base.len() as f64) * budget.max_ratio {
            return Ok(Apply::Paused {
                next_instr: idx + 1,
                partial: out,
                reason: "per-object expansion ratio budget exceeded".into(),
            });
        }
    }
    if out.len() as u64 != target_sz {
        return Err(format!(
            "delta target size mismatch: program declares {target_sz} but produced {} bytes",
            out.len()
        ));
    }
    Ok(Apply::Done(out))
}
