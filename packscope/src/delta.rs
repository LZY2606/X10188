use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeltaHeader {
    pub base_size: u64,
    pub result_size: u64,
    pub header_len: usize,
}

/// Read one little-endian base-128 varint.
fn read_varint(buf: &[u8], mut pos: usize) -> Option<(u64, usize)> {
    let mut val = 0u64;
    let mut shift = 0u32;
    loop {
        let b = *buf.get(pos)?;
        pos += 1;
        val |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
    Some((val, pos))
}

pub fn read_delta_header(data: &[u8]) -> Result<DeltaHeader, String> {
    let (base_size, p1) = read_varint(data, 0).ok_or("truncated delta base size")?;
    let (result_size, p2) = read_varint(data, p1).ok_or("truncated delta result size")?;
    Ok(DeltaHeader { base_size, result_size, header_len: p2 })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum DeltaOp {
    Insert { start: usize, len: usize },
    Copy { offset: usize, size: usize, start: usize },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeltaInspection {
    pub header: DeltaHeader,
    pub ops: Vec<DeltaOp>,
    pub instruction_bytes: (usize, usize),
    pub output_len: usize,
}

/// Parse delta instructions without applying them (for evidence/display).
pub fn inspect(data: &[u8]) -> Result<DeltaInspection, String> {
    let header = read_delta_header(data)?;
    let mut pos = header.header_len;
    let mut ops = Vec::new();
    while pos < data.len() {
        let start = pos;
        let c = data[pos];
        pos += 1;
        if c & 0x80 != 0 {
            let mut offset = 0usize;
            let mut size = 0usize;
            for i in 0..4 {
                if c & (1 << i) != 0 {
                    offset |= (*data.get(pos).ok_or("truncated copy offset")? as usize) << (8 * i);
                    pos += 1;
                }
            }
            for i in 0..3 {
                if c & (1 << (4 + i)) != 0 {
                    size |= (*data.get(pos).ok_or("truncated copy size")? as usize) << (8 * i);
                    pos += 1;
                }
            }
            if size == 0 {
                size = 0x10000;
            }
            ops.push(DeltaOp::Copy { offset, size, start });
        } else if c != 0 {
            ops.push(DeltaOp::Insert { start, len: c as usize });
            pos += c as usize;
            if pos > data.len() {
                return Err("insert overruns delta stream".into());
            }
        } else {
            return Err("delta opcode 0 is reserved".into());
        }
    }
    let output_len = ops
        .iter()
        .map(|op| match op {
            DeltaOp::Insert { len, .. } => *len,
            DeltaOp::Copy { size, .. } => *size,
        })
        .sum();
    Ok(DeltaInspection {
        header,
        ops,
        instruction_bytes: (header.header_len, data.len()),
        output_len,
    })
}

/// Apply delta instructions to `base`, producing the result.
pub fn apply(base: &[u8], delta: &[u8]) -> Result<Vec<u8>, String> {
    let info = inspect(delta)?;
    if info.header.base_size as usize != base.len() {
        return Err(format!(
            "delta base size mismatch: header says {}, actual base is {}",
            info.header.base_size,
            base.len()
        ));
    }
    let mut out = Vec::with_capacity(info.header.result_size as usize);
    for op in &info.ops {
        match op {
            DeltaOp::Insert { start, len } => {
                let begin = start + 1;
                let end = begin + len;
                if end > delta.len() {
                    return Err("insert data out of delta bounds".into());
                }
                out.extend_from_slice(&delta[begin..end]);
            }
            DeltaOp::Copy { offset, size, .. } => {
                let end = offset.checked_add(*size).ok_or("copy range overflow")?;
                if end > base.len() {
                    return Err(format!(
                        "copy out of base bounds: [{}, {}) but base is {}",
                        offset,
                        end,
                        base.len()
                    ));
                }
                out.extend_from_slice(&base[*offset..end]);
            }
        }
        if out.len() > info.header.result_size as usize {
            return Err(format!("output exceeds declared result size {}", info.header.result_size));
        }
    }
    if out.len() != info.header.result_size as usize {
        return Err(format!(
            "result size spoof: header says {}, produced {}",
            info.header.result_size,
            out.len()
        ));
    }
    Ok(out)
}
