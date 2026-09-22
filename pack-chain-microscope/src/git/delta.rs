use super::checksum::sha1_hex;
use super::pack::parse_delta_sizes;

#[derive(Debug, Clone)]
pub struct DeltaInstruction {
    pub index: u32,
    pub op: String,
    /// Byte range of the instruction (including operands) within the delta body.
    pub range_start: u64,
    pub range_end: u64,
    pub length: u64,
    /// Copy source offset within the base (copy ops only).
    pub src_offset: Option<u64>,
    /// Output cursor before/after applying the instruction.
    pub out_before: u64,
    pub out_after: u64,
}

#[derive(Debug, Clone)]
pub struct DeltaApplyError {
    pub code: String,
    pub message: String,
    /// Instruction index where the failure occurred, if applicable.
    pub instruction: Option<u32>,
}

#[derive(Debug)]
pub struct DeltaApplyResult {
    pub expected_base_size: u64,
    pub expected_result_size: u64,
    pub instructions: Vec<DeltaInstruction>,
    pub output: Vec<u8>,
    pub payload_checksum: String,
    /// false when the declared result size differs from the produced length.
    pub size_ok: bool,
}

fn apply_err(code: &str, msg: String, instr: Option<u32>) -> DeltaApplyError {
    DeltaApplyError {
        code: code.into(),
        message: msg,
        instruction: instr,
    }
}

/// Apply a Git thin/delta body against `base`, recording full forensic detail.
pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<DeltaApplyResult, DeltaApplyError> {
    let (expected_base_size, expected_result_size, header_len) =
        parse_delta_sizes(delta).ok_or_else(|| {
            apply_err("bad_delta_header", "delta size varints malformed".into(), None)
        })?;
    if expected_base_size as usize != base.len() {
        return Err(apply_err(
            "base_size_mismatch",
            format!(
                "delta declares base size {} but base is {} bytes",
                expected_base_size,
                base.len()
            ),
            None,
        ));
    }

    let mut out: Vec<u8> = Vec::with_capacity(expected_result_size.min(1 << 28) as usize);
    let mut p = header_len;
    let mut instructions = Vec::new();
    let mut idx: u32 = 0;

    while p < delta.len() {
        let op_start = p;
        let opcode = delta[p];
        p += 1;
        let out_before = out.len() as u64;

        if opcode & 0x80 != 0 {
            // COPY: assemble offset and size from set bits.
            let mut offset: u32 = 0;
            let mut size: u32 = 0;
            for bit in 0..4 {
                if opcode & (1 << bit) != 0 {
                    if p >= delta.len() {
                        return Err(apply_err(
                            "truncated_copy_offset",
                            "copy offset operand missing".into(),
                            Some(idx),
                        ));
                    }
                    offset |= (delta[p] as u32) << (bit * 8);
                    p += 1;
                }
            }
            for bit in 0..3 {
                if opcode & (1 << (4 + bit)) != 0 {
                    if p >= delta.len() {
                        return Err(apply_err(
                            "truncated_copy_size",
                            "copy size operand missing".into(),
                            Some(idx),
                        ));
                    }
                    size |= (delta[p] as u32) << (bit * 8);
                    p += 1;
                }
            }
            if size == 0 {
                size = 0x10000;
            }
            let start = offset as usize;
            let end = start.checked_add(size as usize).ok_or_else(|| {
                apply_err(
                    "copy_overflow",
                    "copy length overflows address space".into(),
                    Some(idx),
                )
            })?;
            if end > base.len() {
                return Err(apply_err(
                    "copy_out_of_bounds",
                    format!(
                        "copy [{}, {}) outside {} byte base",
                        start,
                        end,
                        base.len()
                    ),
                    Some(idx),
                ));
            }
            out.extend_from_slice(&base[start..end]);
            instructions.push(DeltaInstruction {
                index: idx,
                op: "copy".into(),
                range_start: op_start as u64,
                range_end: p as u64,
                length: size as u64,
                src_offset: Some(offset as u64),
                out_before,
                out_after: out.len() as u64,
            });
        } else if opcode != 0 {
            // INSERT
            let len = opcode as usize;
            if p + len > delta.len() {
                return Err(apply_err(
                    "insert_truncated",
                    format!("insert needs {} bytes but only {} remain", len, delta.len() - p),
                    Some(idx),
                ));
            }
            out.extend_from_slice(&delta[p..p + len]);
            p += len;
            instructions.push(DeltaInstruction {
                index: idx,
                op: "insert".into(),
                range_start: op_start as u64,
                range_end: p as u64,
                length: len as u64,
                src_offset: None,
                out_before,
                out_after: out.len() as u64,
            });
        } else {
            return Err(apply_err(
                "bad_opcode",
                "delta opcode 0 is reserved".into(),
                Some(idx),
            ));
        }
        idx += 1;
    }

    let size_ok = out.len() as u64 == expected_result_size;
    let payload_checksum = sha1_hex(&out);
    Ok(DeltaApplyResult {
        expected_base_size,
        expected_result_size,
        instructions,
        output: out,
        payload_checksum,
        size_ok,
    })
}
