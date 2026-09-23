use crate::zlibutil::{inflate_guarded, InflateOutcome};

#[derive(Debug)]
pub struct DeltaData {
    pub source_size: u64,
    pub target_size: u64,
    pub instructions: Vec<u8>,
}

pub fn read_varint(d: &[u8], pos: &mut usize) -> Result<u64, String> {
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        if *pos >= d.len() {
            return Err("delta varint truncated".into());
        }
        let b = d[*pos];
        *pos += 1;
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err("delta varint too long".into());
        }
    }
    Ok(result)
}

/// Inflate a delta entry's compressed payload and parse its size header.
/// `header_declared` is the size from the pack entry header and is checked
/// against the delta stream length so half-way size spoofing is caught.
pub fn load_delta(
    pack: &[u8],
    zlib_start: usize,
    header_declared: u64,
) -> Result<DeltaData, String> {
    let (outcome, data) = inflate_guarded(pack, zlib_start, header_declared);
    let data = match outcome {
        InflateOutcome::Exact { .. } => data,
        other => return Err(format!("delta inflate failed: {:?}", other)),
    };
    let mut pos = 0usize;
    let source_size = read_varint(&data, &mut pos).map_err(|e| e)?;
    let target_size = read_varint(&data, &mut pos).map_err(|e| e)?;
    let instructions = data[pos..].to_vec();
    Ok(DeltaData {
        source_size,
        target_size,
        instructions,
    })
}

#[derive(Debug, Clone)]
pub struct OpRange {
    pub start: usize,
    pub end: usize,
    pub kind: &'static str,
    pub detail: String,
}

pub struct ApplyReport {
    pub output: Vec<u8>,
    pub ops: Vec<OpRange>,
}

/// Apply git delta instructions to `base`.
/// Instruction bytes are indexed within the instruction section.
pub fn apply_delta(base: &[u8], delta: &DeltaData) -> Result<ApplyReport, String> {
    if base.len() as u64 != delta.source_size {
        return Err(format!(
            "delta source size mismatch: base {} vs delta {}",
            base.len(),
            delta.source_size
        ));
    }
    let d = &delta.instructions;
    let mut pos = 0usize;
    let mut out: Vec<u8> = Vec::with_capacity(delta.target_size as usize);
    let mut ops = Vec::new();
    while pos < d.len() {
        let op_start = pos;
        let op = d[pos];
        pos += 1;
        if op & 0x80 != 0 {
            // copy from base
            let mut offset = 0u32;
            let mut size = 0u32;
            for i in 0..4 {
                if op & (1 << i) != 0 {
                    if pos >= d.len() {
                        return Err("copy offset truncated".into());
                    }
                    offset |= (d[pos] as u32) << (8 * i);
                    pos += 1;
                }
            }
            for i in 0..3 {
                if op & (1 << (4 + i)) != 0 {
                    if pos >= d.len() {
                        return Err("copy size truncated".into());
                    }
                    size |= (d[pos] as u32) << (8 * i);
                    pos += 1;
                }
            }
            if size == 0 {
                size = 0x10000;
            }
            let end = offset.checked_add(size).ok_or("copy range overflow")? as usize;
            if end > base.len() {
                return Err(format!(
                    "copy out of range: base {} offset {} size {}",
                    base.len(),
                    offset,
                    size
                ));
            }
            out.extend_from_slice(&base[offset as usize..end]);
            ops.push(OpRange {
                start: op_start,
                end: pos,
                kind: "copy",
                detail: format!("offset={} size={}", offset, size),
            });
        } else if op != 0 {
            // insert literal
            let n = op as usize;
            if pos + n > d.len() {
                return Err("insert literal truncated".into());
            }
            out.extend_from_slice(&d[pos..pos + n]);
            pos += n;
            ops.push(OpRange {
                start: op_start,
                end: pos,
                kind: "insert",
                detail: format!("size={}", n),
            });
        } else {
            return Err("invalid delta opcode 0".into());
        }
        if out.len() as u64 > delta.target_size {
            return Err(format!(
                "delta output exceeded declared target {} (got {})",
                delta.target_size,
                out.len()
            ));
        }
    }
    if out.len() as u64 != delta.target_size {
        return Err(format!(
            "delta target size mismatch: declared {} produced {}",
            delta.target_size,
            out.len()
        ));
    }
    Ok(ApplyReport { output: out, ops })
}
