use serde::Serialize;

/// One delta instruction with its byte range inside the delta payload.
#[derive(Debug, Clone, Serialize)]
pub struct Instr {
    pub start: usize,
    pub end: usize,
    pub kind: String,
    pub offset: u64,
    pub size: u64,
}

fn read_varint(delta: &[u8], i: &mut usize) -> Result<u64, String> {
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        if *i >= delta.len() {
            return Err("truncated delta header varint".to_string());
        }
        let b = delta[*i];
        *i += 1;
        value |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return Ok(value);
        }
        if shift > 63 {
            return Err("delta varint overflow".to_string());
        }
    }
}

/// Apply a Git delta to `base`, returning the output and every instruction
/// (with byte ranges) so each step can be audited.
pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<(Vec<u8>, Vec<Instr>), String> {
    let mut i = 0usize;
    let base_size = read_varint(delta, &mut i)?;
    if base_size != base.len() as u64 {
        return Err(format!(
            "delta base size mismatch: header says {base_size}, actual base is {}",
            base.len()
        ));
    }
    let result_size = read_varint(delta, &mut i)?;
    let mut out = Vec::with_capacity((result_size as usize).min(1 << 26));
    let mut instrs = Vec::new();
    while i < delta.len() {
        let start = i;
        let cmd = delta[i];
        i += 1;
        if cmd & 0x80 != 0 {
            let mut offset = 0u64;
            let mut size = 0u64;
            for bit in 0..4 {
                if cmd & (1 << bit) != 0 {
                    if i >= delta.len() {
                        return Err("truncated copy offset".to_string());
                    }
                    offset |= (delta[i] as u64) << (8 * bit);
                    i += 1;
                }
            }
            for bit in 0..3 {
                if cmd & (0x10 << bit) != 0 {
                    if i >= delta.len() {
                        return Err("truncated copy size".to_string());
                    }
                    size |= (delta[i] as u64) << (8 * bit);
                    i += 1;
                }
            }
            if size == 0 {
                size = 0x10000;
            }
            let end = offset
                .checked_add(size)
                .ok_or_else(|| "copy range overflow".to_string())?;
            if end > base.len() as u64 {
                return Err(format!(
                    "copy out of range: {offset}..{end} beyond base {}",
                    base.len()
                ));
            }
            out.extend_from_slice(&base[offset as usize..end as usize]);
            instrs.push(Instr { start, end: i, kind: "copy".to_string(), offset, size });
        } else if cmd != 0 {
            let n = cmd as usize;
            if i + n > delta.len() {
                return Err("truncated insert".to_string());
            }
            out.extend_from_slice(&delta[i..i + n]);
            i += n;
            instrs.push(Instr { start, end: i, kind: "insert".to_string(), offset: 0, size: n as u64 });
        } else {
            return Err("reserved delta opcode 0".to_string());
        }
    }
    if out.len() as u64 != result_size {
        return Err(format!(
            "delta result size fraud: header says {result_size}, produced {}",
            out.len()
        ));
    }
    Ok((out, instrs))
}
