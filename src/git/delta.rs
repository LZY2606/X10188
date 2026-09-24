//! Git delta encoding: size headers plus insert/copy instructions.
//!
//! Every instruction is recorded with its exact byte range inside the
//! inflated delta buffer, so the UI can show "指令范围" as forensic evidence.

use super::types::Fault;
use super::varint;

/// One applied delta instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Instr {
    Copy {
        src_offset: usize,
        size: usize,
        /// `[start, end)` byte range of this instruction in the delta buffer.
        range: (usize, usize),
    },
    Insert {
        /// `[start, end)` byte range; the literal payload is `end - start - 1`.
        range: (usize, usize),
    },
}

#[derive(Clone, Debug)]
pub struct DeltaDetail {
    pub base_size: u64,
    pub result_size: u64,
    /// Offset where the two size varints end and instructions begin.
    pub instr_start: usize,
    pub instructions: Vec<Instr>,
    pub input_len: usize,
    pub output_len: usize,
    /// True when base length and output length both match declared sizes.
    pub checksum_ok: bool,
}

/// Reads `(base_size, result_size, instructions_start)`.
pub fn parse_sizes(delta: &[u8]) -> Result<(u64, u64, usize), Fault> {
    let (base_size, n1) = varint::read(delta).ok_or(Fault::DeltaTooShort)?;
    let (result_size, n2) =
        varint::read(&delta[n1..]).ok_or(Fault::DeltaTooShort)?;
    Ok((base_size, result_size, n1 + n2))
}

/// Applies `delta` to `base`, enforcing `max_output` bytes.
pub fn apply(base: &[u8], delta: &[u8], max_output: usize) -> Result<(Vec<u8>, DeltaDetail), Fault> {
    let (base_size, result_size, instr_start) = parse_sizes(delta)?;
    if base.len() as u64 != base_size {
        return Err(Fault::DeltaBadSize {
            which: "base",
            expected: base_size,
            got: base.len() as u64,
        });
    }
    if result_size > max_output as u64 {
        return Err(Fault::DeltaBadSize {
            which: "result",
            expected: result_size,
            got: max_output as u64,
        });
    }

    let mut out = Vec::with_capacity(result_size as usize);
    let mut instructions = Vec::new();
    let mut pos = instr_start;

    while pos < delta.len() {
        let opcode = delta[pos];
        let start = pos;
        pos += 1;
        if opcode == 0 {
            return Err(Fault::BadHeader("delta opcode 0 is reserved".into()));
        }
        if opcode & 0x80 != 0 {
            // COPY: four offset presence bits, three size presence bits.
            let mut src_offset: usize = 0;
            for bit in 0..4u32 {
                if opcode & (1 << bit) != 0 {
                    let b = *delta.get(pos).ok_or(Fault::DeltaTooShort)? as usize;
                    pos += 1;
                    src_offset |= b << (8 * bit);
                }
            }
            let mut size: usize = 0;
            for bit in 0..3u32 {
                if opcode & (1 << (4 + bit)) != 0 {
                    let b = *delta.get(pos).ok_or(Fault::DeltaTooShort)? as usize;
                    pos += 1;
                    size |= b << (8 * bit);
                }
            }
            if size == 0 {
                size = 0x10000;
            }
            let end = src_offset.checked_add(size).ok_or(Fault::DeltaBadCopy {
                offset: src_offset,
                size,
                base_len: base.len(),
            })?;
            if end > base.len() {
                return Err(Fault::DeltaBadCopy {
                    offset: src_offset,
                    size,
                    base_len: base.len(),
                });
            }
            out.extend_from_slice(&base[src_offset..end]);
            instructions.push(Instr::Copy {
                src_offset,
                size,
                range: (start, pos),
            });
        } else {
            // INSERT: next `opcode` bytes are literal.
            let len = opcode as usize;
            let end = pos.checked_add(len).ok_or(Fault::DeltaTooShort)?;
            if end > delta.len() {
                return Err(Fault::DeltaTooShort);
            }
            out.extend_from_slice(&delta[pos..end]);
            pos = end;
            instructions.push(Instr::Insert { range: (start, end) });
        }
        if out.len() > result_size as usize {
            return Err(Fault::DeltaInsertsOverrun);
        }
    }

    let checksum_ok = out.len() as u64 == result_size && base.len() as u64 == base_size;
    if !checksum_ok {
        return Err(Fault::DeltaBadSize {
            which: "result",
            expected: result_size,
            got: out.len() as u64,
        });
    }

    Ok((
        out,
        DeltaDetail {
            base_size,
            result_size,
            instr_start,
            instructions,
            input_len: base.len(),
            output_len: out.len(),
            checksum_ok,
        },
    ))
}

/// Encoding side, used by the test fixture builder.
pub enum DeltaOp {
    Insert(Vec<u8>),
    Copy { offset: usize, size: usize },
}

/// Builds a delta from explicit operations. Caller guarantees the operations
/// reproduce the intended result.
pub fn encode(base_size: usize, result_size: usize, ops: &[DeltaOp]) -> Vec<u8> {
    let mut out = Vec::new();
    varint::write(base_size as u64, &mut out);
    varint::write(result_size as u64, &mut out);
    for op in ops {
        match op {
            DeltaOp::Insert(data) => {
                assert!(!data.is_empty() && data.len() <= 127, "insert size 1..=127");
                out.push(data.len() as u8);
                out.extend_from_slice(data);
            }
            DeltaOp::Copy { offset, size } => {
                let mut opcode = 0x80u8;
                let mut bytes = [0u8; 7];
                let mut n = 0;
                for bit in 0..4u32 {
                    let byte = (*offset >> (8 * bit)) & 0xff;
                    if byte != 0 {
                        opcode |= 1 << bit;
                        bytes[n] = byte as u8;
                        n += 1;
                    }
                }
                let effective = if *size == 0x10000 { 0 } else { *size };
                for bit in 0..3u32 {
                    let byte = (effective >> (8 * bit)) & 0xff;
                    if byte != 0 {
                        opcode |= 1 << (4 + bit);
                        bytes[n] = byte as u8;
                        n += 1;
                    }
                }
                out.push(opcode);
                out.extend_from_slice(&bytes[..n]);
            }
        }
    }
    out
}

/// Convenience: delta that appends `suffix` onto a full copy of the base.
pub fn append_delta(base: &[u8], suffix: &[u8]) -> Vec<u8> {
    let result_len = base.len() + suffix.len();
    let mut ops = Vec::new();
    if !base.is_empty() {
        ops.push(DeltaOp::Copy { offset: 0, size: base.len() });
    }
    for chunk in suffix.chunks(127) {
        ops.push(DeltaOp::Insert(chunk.to_vec()));
    }
    encode(base.len(), result_len, &ops)
}
