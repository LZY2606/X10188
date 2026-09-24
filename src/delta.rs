use crate::formats::read_size_encoding;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeltaInstr {
    pub op: String,
    pub range_start: usize,
    pub range_end: usize,
    pub offset: usize,
    pub length: usize,
    pub insert: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeltaReport {
    pub source_size: usize,
    pub target_size: usize,
    pub instructions: Vec<DeltaInstr>,
}

pub fn parse_delta(data: &[u8], base: &[u8]) -> Result<(Vec<u8>, DeltaReport), String> {
    let (source_size, p1) = read_size_encoding(data, 0)?;
    let (target_size, mut pos) = read_size_encoding(data, p1)?;
    if source_size as usize != base.len() {
        return Err(format!(
            "delta base size {source_size} does not match reconstructed base length {}",
            base.len()
        ));
    }
    let mut output = Vec::with_capacity(target_size as usize);
    let mut report = DeltaReport {
        source_size: source_size as usize,
        target_size: target_size as usize,
        instructions: Vec::new(),
    };
    while pos < data.len() {
        let op_start = pos;
        let opcode = data[pos];
        pos += 1;
        if opcode & 0x80 != 0 {
            let mut offset = 0usize;
            let mut length = 0usize;
            for bit in 0..4 {
                if opcode & (1 << bit) != 0 {
                    if pos >= data.len() {
                        return Err("truncated copy offset".into());
                    }
                    offset |= usize::from(data[pos]) << (8 * bit);
                    pos += 1;
                }
            }
            for bit in 0..3 {
                if opcode & (1 << (4 + bit)) != 0 {
                    if pos >= data.len() {
                        return Err("truncated copy length".into());
                    }
                    length |= usize::from(data[pos]) << (8 * bit);
                    pos += 1;
                }
            }
            if length == 0 {
                length = 0x10000;
            }
            if offset.checked_add(length).map_or(true, |end| end > base.len()) {
                return Err(format!(
                    "copy range {offset}+{length} is outside base of {}",
                    base.len()
                ));
            }
            if output.len() + length > target_size as usize {
                return Err("copy exceeds declared target size".into());
            }
            output.extend_from_slice(&base[offset..offset + length]);
            report.instructions.push(DeltaInstr {
                op: "copy".into(),
                range_start: op_start,
                range_end: pos,
                offset,
                length,
                insert: None,
            });
        } else if opcode != 0 {
            let length = opcode as usize;
            if pos + length > data.len() {
                return Err("insert payload is truncated".into());
            }
            if output.len() + length > target_size as usize {
                return Err("insert exceeds declared target size".into());
            }
            let bytes = data[pos..pos + length].to_vec();
            output.extend_from_slice(&bytes);
            pos += length;
            report.instructions.push(DeltaInstr {
                op: "insert".into(),
                range_start: op_start,
                range_end: pos,
                offset: 0,
                length,
                insert: Some(bytes),
            });
        } else {
            return Err("delta opcode zero is reserved".into());
        }
    }
    if output.len() != target_size as usize {
        return Err(format!(
            "delta target size {target_size} does not match produced length {}",
            output.len()
        ));
    }
    Ok((output, report))
}

pub fn build_delta(base: &[u8], target: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    crate::formats::write_size_encoding(base.len() as u64, &mut out);
    crate::formats::write_size_encoding(target.len() as u64, &mut out);
    for chunk in target.chunks(127) {
        out.push(chunk.len() as u8);
        out.extend_from_slice(chunk);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copies_and_inserts() {
        let base = b"hello git object";
        let target = b"say hello git object!";
        let delta = build_delta(base, target);
        let (restored, report) = parse_delta(&delta, base).unwrap();
        assert_eq!(restored, target);
        assert_eq!(report.source_size, base.len());
        assert_eq!(report.target_size, target.len());
        assert!(report.instructions.iter().all(|item| item.op == "insert"));

        let mut copy_delta = vec![16, 19, 3, 11];
        copy_delta.push(0x80 | 0x01);
        copy_delta.extend_from_slice(&6u32.to_le_bytes()[..2]);
        copy_delta.extend_from_slice(&10u32.to_le_bytes()[..1]);
        let (restored_copy, copy_report) = parse_delta(&copy_delta, base).unwrap();
        assert_eq!(restored_copy, b"say git ob");
        assert_eq!(copy_report.instructions[0].offset, 6);
        assert_eq!(copy_report.instructions[0].length, 10);
    }
}
