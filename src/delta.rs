//! Git pack delta handling: header size varints, ofs-delta offset varints,
//! and delta instruction application with per-step provenance.

/// Result of applying one delta against a materialized base.
#[derive(Debug, Clone)]
pub struct DeltaOutcome {
    pub data: Vec<u8>,
    pub steps: Vec<DeltaStep>,
    /// Declared base/target sizes from the delta header.
    pub base_size: u64,
    pub target_size: u64,
}

#[derive(Debug, Clone)]
pub struct DeltaStep {
    /// Byte range [start,end) within the *delta* stream (including op byte).
    pub instr_range: (usize, usize),
    pub kind: StepKind,
    /// Bytes consumed from base (for copy) or inserted (for insert).
    pub count: usize,
    /// Base-relative source range for copy ops.
    pub src_range: Option<(usize, usize)>,
    /// Output range produced by this instruction.
    pub out_range: (usize, usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepKind {
    Insert,
    Copy,
}

impl serde::Serialize for StepKind {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(match self {
            StepKind::Insert => "insert",
            StepKind::Copy => "copy",
        })
    }
}

/// Little-endian base-128 varint used for delta header sizes.
pub fn read_size_varint(buf: &[u8], pos: &mut usize) -> Result<u64, String> {
    let mut result: u64 = 0;
    let mut shift = 0;
    loop {
        if *pos >= buf.len() {
            return Err("delta size varint overruns buffer".into());
        }
        let b = buf[*pos];
        *pos += 1;
        result |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err("delta size varint too long".into());
        }
    }
    Ok(result)
}

/// Negative-offset encoding for OFS_DELTA, starting at `buf[pos]`.
pub fn read_ofs_delta(buf: &[u8], pos: &mut usize) -> Result<u64, String> {
    if *pos >= buf.len() {
        return Err("ofs-delta offset missing".into());
    }
    let mut b = buf[*pos];
    *pos += 1;
    let mut ofs = u64::from(b & 0x7f);
    while b & 0x80 != 0 {
        if *pos >= buf.len() {
            return Err("ofs-delta offset varint overruns pack".into());
        }
        b = buf[*pos];
        *pos += 1;
        ofs = ofs
            .checked_add(1)
            .and_then(|v| v.checked_shl(7))
            .ok_or_else(|| "ofs-delta offset overflow".to_string())?;
        ofs += u64::from(b & 0x7f);
    }
    Ok(ofs)
}

/// Apply delta instructions to `base`, producing the target object payload.
///
/// `delta` starts at the two size varints. Every instruction is recorded with
/// its exact byte range so the UI can show command provenance.
pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<DeltaOutcome, String> {
    let mut pos = 0usize;
    let base_size = read_size_varint(delta, &mut pos)?;
    let target_size = read_size_varint(delta, &mut pos)?;

    if base_size as usize != base.len() {
        return Err(format!(
            "delta base size mismatch: header {base_size}, actual {}",
            base.len()
        ));
    }

    let mut steps: Vec<DeltaStep> = Vec::new();
    let mut out: Vec<u8> = Vec::with_capacity(target_size as usize);

    while pos < delta.len() {
        let start = pos;
        let op = delta[pos];
        pos += 1;
        if op & 0x80 != 0 {
            // COPY: up to 7 offset bytes (little endian), then 7 size bytes.
            let mut off: u32 = 0;
            let mut len: u32 = 0;
            for i in 0..4 {
                if op & (1 << i) != 0 {
                    if pos >= delta.len() {
                        return Err("copy offset overruns delta".into());
                    }
                    off |= u32::from(delta[pos]) << (8 * i);
                    pos += 1;
                }
            }
            for i in 0..3 {
                if op & (1 << (4 + i)) != 0 {
                    if pos >= delta.len() {
                        return Err("copy size overruns delta".into());
                    }
                    len |= u32::from(delta[pos]) << (8 * i);
                    pos += 1;
                }
            }
            if len == 0 {
                len = 0x10000;
            }
            let off = off as usize;
            let len = len as usize;
            let src_end = off.checked_add(len).ok_or("copy offset+len overflow")?;
            if src_end > base.len() {
                return Err(format!(
                    "copy out of base range: off={off} len={len} base={}",
                    base.len()
                ));
            }
            let out_start = out.len();
            out.extend_from_slice(&base[off..src_end]);
            steps.push(DeltaStep {
                instr_range: (start, pos),
                kind: StepKind::Copy,
                count: len,
                src_range: Some((off, src_end)),
                out_range: (out_start, out_start + len),
            });
        } else if op != 0 {
            // INSERT: op is the literal length (1..=127).
            let len = op as usize;
            if pos + len > delta.len() {
                return Err("insert overruns delta stream".into());
            }
            let out_start = out.len();
            out.extend_from_slice(&delta[pos..pos + len]);
            pos += len;
            steps.push(DeltaStep {
                instr_range: (start, pos),
                kind: StepKind::Insert,
                count: len,
                src_range: None,
                out_range: (out_start, out_start + len),
            });
        } else {
            return Err("delta opcode 0 is reserved".into());
        }
    }

    if out.len() as u64 != target_size {
        return Err(format!(
            "delta target size mismatch: header {target_size}, produced {}",
            out.len()
        ));
    }

    Ok(DeltaOutcome {
        data: out,
        steps,
        base_size,
        target_size,
    })
}
