use crate::git::varint::read_leb128;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InstrKind {
    Copy,
    Insert,
}

#[derive(Clone, Debug)]
pub struct Instr {
    pub kind: InstrKind,
    /// Byte range covering the opcode and any parameters in the delta buffer.
    pub range_start: usize,
    pub range_end: usize,
    pub src_offset: u64,
    pub length: u64,
    /// Offset in the reconstructed target stream.
    pub out_offset: u64,
}

#[derive(Debug)]
pub struct DeltaResult {
    pub target: Vec<u8>,
    pub base_size: u64,
    pub result_size: u64,
    pub instrs: Vec<Instr>,
}

pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<DeltaResult, String> {
    let (base_size, p1) = read_leb128(delta, 0)?;
    if base_size as usize != base.len() {
        return Err(format!(
            "delta source size mismatch: header says {base_size}, base is {}",
            base.len()
        ));
    }
    let (result_size, mut pos) = read_leb128(delta, p1)?;
    let mut out: Vec<u8> = Vec::new();
    let mut instrs: Vec<Instr> = Vec::new();
    let mut out_pos: u64 = 0;

    while pos < delta.len() {
        let opcode = delta[pos];
        let start = pos;
        pos += 1;
        if opcode == 0 {
            return Err("invalid delta opcode 0".into());
        }
        if opcode & 0x80 != 0 {
            let mut offset: u32 = 0;
            let mut size: u32 = 0;
            if opcode & 0x01 != 0 {
                offset |= delta[pos] as u32;
                pos += 1;
            }
            if opcode & 0x02 != 0 {
                offset |= (delta[pos] as u32) << 8;
                pos += 1;
            }
            if opcode & 0x04 != 0 {
                offset |= (delta[pos] as u32) << 16;
                pos += 1;
            }
            if opcode & 0x08 != 0 {
                offset |= (delta[pos] as u32) << 24;
                pos += 1;
            }
            if opcode & 0x10 != 0 {
                size |= delta[pos] as u32;
                pos += 1;
            }
            if opcode & 0x20 != 0 {
                size |= (delta[pos] as u32) << 8;
                pos += 1;
            }
            if opcode & 0x40 != 0 {
                size |= (delta[pos] as u32) << 16;
                pos += 1;
            }
            if size == 0 {
                size = 0x10000;
            }
            let end = offset as u64 + size as u64;
            if end > base.len() as u64 {
                return Err(format!(
                    "COPY overruns base: offset {offset} size {size} but base len {}",
                    base.len()
                ));
            }
            out.extend_from_slice(&base[offset as usize..(offset + size) as usize]);
            instrs.push(Instr {
                kind: InstrKind::Copy,
                range_start: start,
                range_end: pos,
                src_offset: offset as u64,
                length: size as u64,
                out_offset: out_pos,
            });
            out_pos += size as u64;
        } else {
            let n = opcode as usize;
            if pos + n > delta.len() {
                return Err("INSERT runs past end of delta".into());
            }
            out.extend_from_slice(&delta[pos..pos + n]);
            pos += n;
            instrs.push(Instr {
                kind: InstrKind::Insert,
                range_start: start,
                range_end: pos,
                src_offset: 0,
                length: n as u64,
                out_offset: out_pos,
            });
            out_pos += n as u64;
        }
        if out_pos > result_size {
            return Err(format!(
                "reconstructed stream ({out_pos}) exceeds declared target size {result_size}"
            ));
        }
    }

    if out.len() as u64 != result_size {
        return Err(format!(
            "delta target size mismatch: header says {result_size}, produced {}",
            out.len()
        ));
    }
    Ok(DeltaResult {
        target: out,
        base_size,
        result_size,
        instrs,
    })
}
