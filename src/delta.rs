use crate::git::{encode_delta_varint, read_delta_varint, ObjectType};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeltaOperation { Copy, Insert }

#[derive(Debug, Clone)]
pub struct DeltaInstruction {
    pub index: usize,
    pub operation: DeltaOperation,
    pub instruction_start: usize,
    pub instruction_end: usize,
    pub source_start: u64,
    pub source_len: u64,
    pub target_offset: u64,
}

#[derive(Debug, Clone)]
pub struct DeltaApplication {
    pub object_type: ObjectType,
    pub data: Vec<u8>,
    pub instructions: Vec<DeltaInstruction>,
}

#[derive(Debug, Clone)]
pub struct BudgetConfig {
    pub max_depth: usize,
    pub max_total_expanded: u64,
    pub max_single_object: u64,
    pub single_object_ratio: u64,
}

impl Default for BudgetConfig {
    fn default() -> Self {
        Self { max_depth: 16, max_total_expanded: 64 * 1024 * 1024, max_single_object: 16 * 1024 * 1024, single_object_ratio: 100 }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct BudgetUsage {
    pub depth: usize,
    pub expanded_bytes: u64,
    pub chain_input_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeltaError {
    Truncated,
    BadSize { expected: u64, actual: u64 },
    BadCopyRange { start: u64, len: u64, base_len: u64 },
    OutputLimit(u64),
    TotalBudget(u64),
    DepthLimit(usize),
    ZeroCopyLength,
}

impl DeltaError {
    pub fn message(&self) -> String {
        match self {
            Self::Truncated => "delta instruction stream is truncated".into(),
            Self::BadSize { expected, actual } => format!("delta result size spoof: header says {expected}, produced {actual}"),
            Self::BadCopyRange { start, len, base_len } => format!("copy range {start}..{} exceeds base length {base_len}", start + len),
            Self::OutputLimit(v) => format!("single-object output budget reached at {v} bytes"),
            Self::TotalBudget(v) => format!("total expanded-byte budget reached after {v} bytes"),
            Self::DepthLimit(v) => format!("delta depth budget reached at depth {v}"),
            Self::ZeroCopyLength => "delta copy opcode encodes zero length".into(),
        }
    }
}

pub fn apply_delta(kind: ObjectType, base: &[u8], delta: &[u8], single_limit: u64) -> Result<DeltaApplication, DeltaError> {
    let mut pos = 0usize;
    let base_size = match read_delta_varint(delta, pos) { Ok((v,p)) => { pos=p; v }, Err(_) => return Err(DeltaError::Truncated) };
    let result_size = match read_delta_varint(delta, pos) { Ok((v,p)) => { pos=p; v }, Err(_) => return Err(DeltaError::Truncated) };
    if base_size as usize != base.len() {
        return Err(DeltaError::BadSize { expected: base.len() as u64, actual: base_size });
    }
    if result_size > single_limit { return Err(DeltaError::OutputLimit(result_size)); }
    let mut out = Vec::with_capacity(result_size.min(single_limit) as usize);
    let mut instructions = Vec::new();
    let mut index = 0usize;
    while pos < delta.len() {
        let op_start = pos;
        let opcode = delta[pos]; pos += 1;
        if opcode & 0x80 != 0 {
            let mut start = 0u32;
            let mut len = 0u32;
            if opcode & 0x01 != 0 { start |= delta[pos] as u32; pos += 1; }
            if opcode & 0x02 != 0 { start |= (delta[pos] as u32) << 8; pos += 1; }
            if opcode & 0x04 != 0 { start |= (delta[pos] as u32) << 16; pos += 1; }
            if opcode & 0x08 != 0 { start |= (delta[pos] as u32) << 24; pos += 1; }
            if opcode & 0x10 != 0 { len |= delta[pos] as u32; pos += 1; }
            if opcode & 0x20 != 0 { len |= (delta[pos] as u32) << 8; pos += 1; }
            if opcode & 0x40 != 0 { len |= (delta[pos] as u32) << 16; pos += 1; }
            if len == 0 { len = 0x10000; }
            let end = start as u64 + len as u64;
            if end > base.len() as u64 { return Err(DeltaError::BadCopyRange { start: start.into(), len: len.into(), base_len: base.len() as u64 }); }
            if len == 0 { return Err(DeltaError::ZeroCopyLength); }
            let target_offset = out.len() as u64;
            out.extend_from_slice(&base[start as usize..end as usize]);
            instructions.push(DeltaInstruction { index, operation: DeltaOperation::Copy, instruction_start: op_start, instruction_end: pos, source_start: start.into(), source_len: len.into(), target_offset });
        } else if opcode > 0 {
            let len = opcode as usize;
            if pos + len > delta.len() { return Err(DeltaError::Truncated); }
            let target_offset = out.len() as u64;
            out.extend_from_slice(&delta[pos..pos + len]);
            pos += len;
            instructions.push(DeltaInstruction { index, operation: DeltaOperation::Insert, instruction_start: op_start, instruction_end: pos, source_start: target_offset, source_len: len as u64, target_offset });
        } else {
            return Err(DeltaError::Truncated);
        }
        if out.len() as u64 > single_limit { return Err(DeltaError::OutputLimit(out.len() as u64)); }
        index += 1;
    }
    if out.len() as u64 != result_size {
        return Err(DeltaError::BadSize { expected: result_size, actual: out.len() as u64 });
    }
    Ok(DeltaApplication { object_type: kind, data: out, instructions })
}

pub fn build_delta(base: &[u8], result: &[u8]) -> Vec<u8> {
    let mut delta = encode_delta_varint(base.len() as u64);
    delta.extend(encode_delta_varint(result.len() as u64));
    let mut pos = 0usize;
    while pos < result.len() {
        if base.is_empty() || pos + 3 > result.len() {
            let take = (result.len() - pos).min(127);
            delta.push(take as u8);
            delta.extend_from_slice(&result[pos..pos+take]);
            pos += take;
            continue;
        }
        let needle = &result[pos..(pos+3).min(result.len())];
        let found = base.windows(needle.len()).position(|w| w == needle);
        match found {
            Some(start) => {
                let mut length = 0usize;
                while start + length < base.len() && pos + length < result.len() && base[start+length] == result[pos+length] { length += 1; }
                let mut opcode = 0x80u8;
                let mut args = Vec::new();
                let vals = [(start & 0xff, 1), ((start >> 8) & 0xff, 2), ((start >> 16) & 0xff, 4), ((start >> 24) & 0xff, 8)];
                for (val, bit) in vals { if val != 0 { opcode |= bit; args.push(val as u8); } }
                let len_vals = [(length & 0xff, 0x10), ((length >> 8) & 0xff, 0x20), ((length >> 16) & 0xff, 0x40)];
                for (val, bit) in len_vals { if val != 0 { opcode |= bit; args.push(val as u8); } }
                delta.push(opcode); delta.extend(args);
                pos += length;
            }
            None => {
                let take = (result.len() - pos).min(127);
                delta.push(take as u8);
                delta.extend_from_slice(&result[pos..pos+take]);
                pos += take;
            }
        }
    }
    delta
}
