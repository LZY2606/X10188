use super::varint::read_varint;
use serde::{Deserialize, Serialize};

/// One recorded delta instruction (or a grouped range of them).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaStep {
    pub kind: String,
    /// Byte range of this instruction inside the delta data.
    pub range_start: usize,
    pub range_end: usize,
    pub src_off: Option<u64>,
    pub src_len: Option<u64>,
    pub insert_len: Option<u64>,
    pub out_len_after: u64,
}

#[derive(Debug, Clone, Default)]
pub struct ApplyStats {
    pub steps: Vec<DeltaStep>,
    pub insert_bytes: u64,
    pub copy_bytes: u64,
}

/// Apply a git delta (base/target size header + copy/insert opcodes) to
/// `base`. `cap` bounds the output size. Every instruction's byte range,
/// lengths and running output size are recorded.
pub fn apply_delta(base: &[u8], delta: &[u8], cap: u64) -> Result<(Vec<u8>, ApplyStats), String> {
    let (base_size, n1) = read_varint(delta).map_err(|e| format!("delta base size: {}", e))?;
    if base_size as usize != base.len() {
        return Err(format!(
            "delta base size mismatch: header {}, actual {}",
            base_size,
            base.len()
        ));
    }
    let (want_size, n2) =
        read_varint(&delta[n1..]).map_err(|e| format!("delta target size: {}", e))?;
    if want_size > cap {
        return Err(format!(
            "delta target size {} exceeds per-object budget {}",
            want_size, cap
        ));
    }
    let mut out = Vec::with_capacity(want_size.min(1 << 24) as usize);
    let mut p = n1 + n2;
    let mut stats = ApplyStats::default();
    while p < delta.len() {
        let op = delta[p];
        let range_start = p;
        p += 1;
        if op & 0x80 != 0 {
            // copy from base
            let mut off: u32 = 0;
            let mut len: u32 = 0;
            for i in 0..4u8 {
                if op & (1 << i) != 0 {
                    if p >= delta.len() {
                        return Err("copy opcode truncated (offset)".into());
                    }
                    off |= (delta[p] as u32) << (i * 8);
                    p += 1;
                }
            }
            for i in 0..3u8 {
                if op & (1 << (4 + i)) != 0 {
                    if p >= delta.len() {
                        return Err("copy opcode truncated (size)".into());
                    }
                    len |= (delta[p] as u32) << (i * 8);
                    p += 1;
                }
            }
            if len == 0 {
                len = 0x10000;
            }
            let start = off as usize;
            let end = start
                .checked_add(len as usize)
                .ok_or_else(|| "copy range overflow".to_string())?;
            if end > base.len() {
                return Err(format!(
                    "copy out of base range: off {} len {} (base {})",
                    off,
                    len,
                    base.len()
                ));
            }
            out.extend_from_slice(&base[start..end]);
            stats.copy_bytes += len as u64;
            stats.steps.push(DeltaStep {
                kind: "copy".into(),
                range_start,
                range_end: p,
                src_off: Some(off as u64),
                src_len: Some(len as u64),
                insert_len: None,
                out_len_after: out.len() as u64,
            });
        } else if op != 0 {
            // insert literal
            let len = op as usize;
            if p + len > delta.len() {
                return Err("insert opcode truncated".into());
            }
            out.extend_from_slice(&delta[p..p + len]);
            p += len;
            stats.insert_bytes += len as u64;
            stats.steps.push(DeltaStep {
                kind: "insert".into(),
                range_start,
                range_end: p,
                src_off: None,
                src_len: None,
                insert_len: Some(len as u64),
                out_len_after: out.len() as u64,
            });
        } else {
            return Err("delta reserved opcode 0".into());
        }
        if out.len() as u64 > cap {
            return Err(format!(
                "delta output exceeded per-object budget {} mid-stream",
                cap
            ));
        }
    }
    if out.len() as u64 != want_size {
        return Err(format!(
            "delta output size mismatch: header {}, produced {}",
            want_size,
            out.len()
        ));
    }
    Ok((out, stats))
}
