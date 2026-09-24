//! Git delta instruction decoder/applier.
//!
//! Every instruction is recorded with its byte range inside the delta blob
//! so the audit trail can show exactly which bytes copied or inserted data.

use crate::binformat::decode_size_varint;
use crate::models::DeltaOp;

#[derive(Debug, Clone)]
pub struct DeltaApplication {
    pub source_size: u64,
    pub target_size: u64,
    pub data_start: usize,
    pub data_end: usize,
    pub output: Vec<u8>,
    pub ops: Vec<DeltaOp>,
    pub exact_target: bool,
    pub error: Option<String>,
}

/// Apply `delta` to `base`, bounded by `max_out` bytes of output.
///
/// The function is allocation-safe: it never produces more than
/// `max_out + 65536` bytes (one copy instruction is allowed to reach the
/// bound so the caller can decide whether the budget was exceeded).
pub fn apply_delta(base: &[u8], delta: &[u8], max_out: usize) -> DeltaApplication {
    let mut result = DeltaApplication {
        source_size: 0,
        target_size: 0,
        data_start: 0,
        data_end: 0,
        output: Vec::new(),
        ops: Vec::new(),
        exact_target: false,
        error: None,
    };

    let (source_size, p1) = match decode_size_varint(delta, 0) {
        Ok(v) => v,
        Err(e) => {
            result.error = Some(e);
            return result;
        }
    };
    let (target_size, p2) = match decode_size_varint(delta, p1) {
        Ok(v) => v,
        Err(e) => {
            result.error = Some(e);
            return result;
        }
    };
    result.source_size = source_size;
    result.target_size = target_size;
    result.data_start = p2;

    if base.len() as u64 != source_size {
        result.error = Some(format!(
            "delta source size {} does not match base length {}",
            source_size,
            base.len()
        ));
        return result;
    }
    if target_size > max_out as u64 {
        // Still parse instructions so partial evidence is available, but cap.
        result.output = Vec::new();
    }

    let mut pos = p2;
    while pos < delta.len() {
        let op_start = pos;
        let op = delta[pos];
        pos += 1;
        if op & 0x80 != 0 {
            // COPY instruction.
            let mut cp_off: u32 = 0;
            let mut cp_size: u32 = 0;
            for bit in 0..4u32 {
                if op & (1 << bit) != 0 {
                    if pos >= delta.len() {
                        result.error = Some("copy instruction offset truncated".into());
                        result.data_end = pos;
                        return result;
                    }
                    cp_off |= (delta[pos] as u32) << (bit * 8);
                    pos += 1;
                }
            }
            for bit in 4..7u32 {
                if op & (1 << bit) != 0 {
                    if pos >= delta.len() {
                        result.error = Some("copy instruction size truncated".into());
                        result.data_end = pos;
                        return result;
                    }
                    cp_size |= (delta[pos] as u32) << ((bit - 4) * 8);
                    pos += 1;
                }
            }
            if cp_size == 0 {
                cp_size = 0x10000;
            }
            let end_src = cp_off as u64 + cp_size as u64;
            if end_src > base.len() as u64 {
                result.error = Some(format!(
                    "copy reads [{}, {}) but base is only {} bytes",
                    cp_off, end_src, base.len()
                ));
                result.ops.push(DeltaOp {
                    kind: "copy".into(),
                    op_start: op_start as u64,
                    op_end: pos as u64,
                    src_off: Some(cp_off as u64),
                    src_len: Some(cp_size as u64),
                    insert_len: None,
                });
                result.data_end = pos;
                return result;
            }
            if result.output.len() as u64 + cp_size as u64 <= max_out as u64
                && target_size <= max_out as u64
            {
                result
                    .output
                    .extend_from_slice(&base[cp_off as usize..cp_off as usize + cp_size as usize]);
            }
            result.ops.push(DeltaOp {
                kind: "copy".into(),
                op_start: op_start as u64,
                op_end: pos as u64,
                src_off: Some(cp_off as u64),
                src_len: Some(cp_size as u64),
                insert_len: None,
            });
        } else if op != 0 {
            // INSERT instruction.
            let len = op as usize;
            if pos + len > delta.len() {
                result.error = Some(format!(
                    "insert declares {} bytes but only {} remain",
                    len,
                    delta.len() - pos
                ));
                result.data_end = pos;
                return result;
            }
            if result.output.len() as u64 + len as u64 <= max_out as u64
                && target_size <= max_out as u64
            {
                result.output.extend_from_slice(&delta[pos..pos + len]);
            }
            result.ops.push(DeltaOp {
                kind: "insert".into(),
                op_start: op_start as u64,
                op_end: (pos + len) as u64,
                src_off: None,
                src_len: None,
                insert_len: Some(len as u64),
            });
            pos += len;
        } else {
            result.error = Some("delta contains reserved zero opcode".into());
            result.data_end = pos;
            return result;
        }
    }

    result.data_end = pos;
    result.exact_target = result.output.len() as u64 == target_size;
    if result.output.len() as u64 != target_size {
        result.error = Some(format!(
            "after all instructions output is {} bytes but target size is {}",
            result.output.len(),
            target_size
        ));
    }
    result
}
