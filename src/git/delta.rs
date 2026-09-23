/// Git delta instruction handling (git documented "thin pack delta" format).
use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CmdKind {
    Copy,
    Insert,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeltaCmd {
    pub kind: CmdKind,
    /// Byte range inside the delta instruction stream [start, end).
    pub range_start: usize,
    pub range_end: usize,
    /// Source (base) span for copy commands.
    pub src_offset: Option<usize>,
    pub src_len: Option<usize>,
    /// Bytes emitted into the target for insert commands.
    pub data_len: usize,
    /// Position in the produced target.
    pub out_offset: usize,
    pub out_len: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeltaMeta {
    pub declared_base_size: usize,
    pub declared_result_size: usize,
    pub header_len: usize,
    pub commands: Vec<DeltaCmd>,
}

#[derive(Debug, Clone)]
pub enum ApplyError {
    Invalid(String),
    OutputTooLarge { declared: usize, limit: usize },
}

pub fn read_size_header(data: &[u8], mut pos: usize) -> Result<(usize, usize), String> {
    let mut shift = 0u32;
    let mut size: usize = 0;
    loop {
        let &b = data.get(pos).ok_or_else(|| "truncated size header".to_string())?;
        size |= ((b & 0x7f) as usize) << shift;
        pos += 1;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 28 {
            return Err("size header too long".into());
        }
    }
    Ok((size, pos))
}

/// Apply `delta` to `base`, honouring a hard result-size cap and recording
/// every instruction's range, source span and produced output span.
pub fn apply_delta(
    base: &[u8],
    delta: &[u8],
    max_result: usize,
) -> Result<(Vec<u8>, DeltaMeta), ApplyError> {
    let (base_size, p1) = read_size_header(delta, 0).map_err(ApplyError::Invalid)?;
    let (result_size, p2) = read_size_header(delta, p1).map_err(ApplyError::Invalid)?;
    if base_size != base.len() {
        return Err(ApplyError::Invalid(format!(
            "delta declares base size {} but base is {}",
            base_size,
            base.len()
        )));
    }
    if result_size > max_result {
        return Err(ApplyError::OutputTooLarge {
            declared: result_size,
            limit: max_result,
        });
    }

    let mut out = Vec::with_capacity(result_size.min(1 << 20));
    let mut pos = p2;
    let mut commands = Vec::new();

    while pos < delta.len() {
        let op = delta[pos];
        let cmd_start = pos;
        if op & 0x80 != 0 {
            // COPY: opcode byte, then up to 4 offset bytes, then 3 size bytes.
            pos += 1;
            let mut cp_off: usize = 0;
            let mut cp_size: usize = 0;
            for i in 0..4 {
                if op & (1 << i) != 0 {
                    let &b = delta
                        .get(pos)
                        .ok_or_else(|| ApplyError::Invalid("truncated copy offset".into()))?;
                    cp_off |= (b as usize) << (8 * i);
                    pos += 1;
                }
            }
            for i in 0..3 {
                if op & (1 << (4 + i)) != 0 {
                    let &b = delta
                        .get(pos)
                        .ok_or_else(|| ApplyError::Invalid("truncated copy size".into()))?;
                    cp_size |= (b as usize) << (8 * i);
                    pos += 1;
                }
            }
            if cp_size == 0 {
                cp_size = 0x10000;
            }
            let end = cp_off
                .checked_add(cp_size)
                .ok_or_else(|| ApplyError::Invalid("copy span overflow".into()))?;
            if end > base.len() {
                return Err(ApplyError::Invalid(format!(
                    "copy range [{},{}) outside base of {}",
                    cp_off,
                    end,
                    base.len()
                )));
            }
            let out_off = out.len();
            out.extend_from_slice(&base[cp_off..end]);
            commands.push(DeltaCmd {
                kind: CmdKind::Copy,
                range_start: cmd_start,
                range_end: pos,
                src_offset: Some(cp_off),
                src_len: Some(cp_size),
                data_len: 0,
                out_offset: out_off,
                out_len: cp_size,
            });
        } else if op != 0 {
            // INSERT
            let len = op as usize;
            if pos + 1 + len > delta.len() {
                return Err(ApplyError::Invalid("insert overruns delta stream".into()));
            }
            let out_off = out.len();
            out.extend_from_slice(&delta[pos + 1..pos + 1 + len]);
            pos += 1 + len;
            commands.push(DeltaCmd {
                kind: CmdKind::Insert,
                range_start: cmd_start,
                range_end: pos,
                src_offset: None,
                src_len: None,
                data_len: len,
                out_offset: out_off,
                out_len: len,
            });
        } else {
            return Err(ApplyError::Invalid(format!(
                "reserved delta opcode 0 at byte {}",
                pos
            )));
        }
        if out.len() > max_result {
            return Err(ApplyError::OutputTooLarge {
                declared: result_size,
                limit: max_result,
            });
        }
    }

    if out.len() != result_size {
        return Err(ApplyError::Invalid(format!(
            "delta declares result size {} but produced {}",
            result_size,
            out.len()
        )));
    }
    Ok((
        out,
        DeltaMeta {
            declared_base_size: base_size,
            declared_result_size: result_size,
            header_len: p2,
            commands,
        },
    ))
}
