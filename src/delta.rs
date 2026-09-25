//! Git delta instruction parsing and application.

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeltaOp {
    /// Byte range of this instruction inside the delta stream: [start, end).
    pub instr_start: usize,
    pub instr_end: usize,
    pub kind: String, // "copy" | "insert"
    /// For copy: offset/len into the base. For insert: len of literal data.
    pub base_offset: usize,
    pub len: usize,
}

#[derive(Debug, Clone)]
pub struct ParsedDelta {
    pub base_size: u64,
    pub result_size: u64,
    /// Offset inside the delta stream where instructions begin.
    pub instr_offset: usize,
    pub ops: Vec<DeltaOp>,
}

fn read_varint(data: &[u8], pos: &mut usize) -> Result<u64, String> {
    let mut v: u64 = 0;
    let mut shift = 0u32;
    loop {
        if *pos >= data.len() {
            return Err("truncated delta varint".into());
        }
        let b = data[*pos];
        *pos += 1;
        v |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return Ok(v);
        }
        if shift > 63 {
            return Err("delta varint overflow".into());
        }
    }
}

pub fn parse_delta(data: &[u8]) -> Result<ParsedDelta, String> {
    let mut pos = 0usize;
    let base_size = read_varint(data, &mut pos)?;
    let result_size = read_varint(data, &mut pos)?;
    let instr_offset = pos;
    let mut ops = Vec::new();
    while pos < data.len() {
        let start = pos;
        let cmd = data[pos];
        pos += 1;
        if cmd & 0x80 != 0 {
            // copy from base
            let mut off: usize = 0;
            let mut size: usize = 0;
            for i in 0..4 {
                if cmd & (1 << i) != 0 {
                    if pos >= data.len() {
                        return Err("truncated copy offset".into());
                    }
                    off |= (data[pos] as usize) << (8 * i);
                    pos += 1;
                }
            }
            for i in 0..3 {
                if cmd & (0x10 << i) != 0 {
                    if pos >= data.len() {
                        return Err("truncated copy size".into());
                    }
                    size |= (data[pos] as usize) << (8 * i);
                    pos += 1;
                }
            }
            if size == 0 {
                size = 0x10000;
            }
            ops.push(DeltaOp {
                instr_start: start,
                instr_end: pos,
                kind: "copy".into(),
                base_offset: off,
                len: size,
            });
        } else if cmd != 0 {
            let n = cmd as usize;
            if pos + n > data.len() {
                return Err(format!(
                    "insert of {n} bytes overruns delta stream ({} left)",
                    data.len() - pos
                ));
            }
            pos += n;
            ops.push(DeltaOp {
                instr_start: start,
                instr_end: pos,
                kind: "insert".into(),
                base_offset: 0,
                len: n,
            });
        } else {
            return Err("delta opcode 0 is reserved".into());
        }
    }
    Ok(ParsedDelta {
        base_size,
        result_size,
        instr_offset,
        ops,
    })
}

/// Apply a parsed delta to `base`, verifying every check a forensic tool
/// should verify. Returns (output, total copied bytes, total inserted bytes).
pub fn apply_delta(
    delta_data: &[u8],
    parsed: &ParsedDelta,
    base: &[u8],
) -> Result<(Vec<u8>, usize, usize), String> {
    if parsed.base_size != base.len() as u64 {
        return Err(format!(
            "delta base size mismatch: delta expects {}, base is {}",
            parsed.base_size,
            base.len()
        ));
    }
    let mut out = Vec::with_capacity(parsed.result_size as usize);
    let mut copied = 0usize;
    let mut inserted = 0usize;
    for op in &parsed.ops {
        if op.kind == "copy" {
            let end = op
                .base_offset
                .checked_add(op.len)
                .ok_or("copy range overflow")?;
            if end > base.len() {
                return Err(format!(
                    "copy [{}, {}) exceeds base length {}",
                    op.base_offset,
                    end,
                    base.len()
                ));
            }
            out.extend_from_slice(&base[op.base_offset..end]);
            copied += op.len;
        } else {
            // insert: literal bytes follow the opcode byte
            let lit_start = op.instr_start + 1;
            out.extend_from_slice(&delta_data[lit_start..lit_start + op.len]);
            inserted += op.len;
        }
    }
    if out.len() as u64 != parsed.result_size {
        return Err(format!(
            "delta result size mismatch: header says {}, produced {}",
            parsed.result_size,
            out.len()
        ));
    }
    Ok((out, copied, inserted))
}
