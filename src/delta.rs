use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectType {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
}

impl ObjectType {
    pub fn from_pack(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Commit),
            2 => Some(Self::Tree),
            3 => Some(Self::Blob),
            4 => Some(Self::Tag),
            6 => Some(Self::OfsDelta),
            7 => Some(Self::RefDelta),
            _ => None,
        }
    }

    pub fn git_name(&self) -> &'static str {
        match self {
            Self::Commit => "commit",
            Self::Tree => "tree",
            Self::Blob => "blob",
            Self::Tag => "tag",
            Self::OfsDelta | Self::RefDelta => "delta",
        }
    }

    pub fn named(name: &str) -> Option<Self> {
        match name {
            "commit" => Some(Self::Commit),
            "tree" => Some(Self::Tree),
            "blob" => Some(Self::Blob),
            "tag" => Some(Self::Tag),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DeltaInstruction {
    pub start: usize,
    pub end: usize,
    pub kind: &'static str,
    pub offset: usize,
    pub length: usize,
}

#[derive(Debug, Clone)]
pub struct AppliedDelta {
    pub target_size: u64,
    pub instructions: Vec<DeltaInstruction>,
    pub output: Vec<u8>,
}

pub fn read_size_encoding(data: &[u8], mut pos: usize) -> Result<(u64, usize)> {
    let mut shift = 0u32;
    let mut value = 0u64;
    loop {
        if pos >= data.len() || shift > 63 {
            return Err(Error::Corrupt("truncated or oversized size encoding".into()));
        }
        let byte = data[pos];
        pos += 1;
        value |= u64::from(byte & 0x7f)
            .checked_shl(shift)
            .ok_or_else(|| Error::Corrupt("size encoding overflow".to_string()))?;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    Ok((value, pos))
}

pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<AppliedDelta> {
    let (source_size, mut pos) = read_size_encoding(delta, 0)?;
    if source_size as usize != base.len() {
        return Err(Error::Corrupt(format!(
            "delta source size {source_size} does not match base length {}",
            base.len()
        )));
    }
    let target_size;
    (target_size, pos) = read_size_encoding(delta, pos)?;
    let header_end = pos;
    let mut output = Vec::with_capacity(target_size.min(64 * 1024) as usize);
    let mut instructions = Vec::new();

    while pos < delta.len() {
        let opcode_pos = pos;
        let opcode = delta[pos];
        pos += 1;
        if opcode & 0x80 != 0 {
            let mut offset = 0usize;
            let mut length = 0usize;
            for bit in 0..4 {
                if opcode & (1 << bit) != 0 {
                    offset |= (delta[pos] as usize) << (bit * 8);
                    pos += 1;
                }
            }
            for bit in 0..3 {
                if opcode & (1 << (4 + bit)) != 0 {
                    length |= (delta[pos] as usize) << (bit * 8);
                    pos += 1;
                }
            }
            if length == 0 {
                length = 0x10000;
            }
            if offset.checked_add(length).map_or(true, |end| end > base.len()) {
                return Err(Error::Corrupt(format!(
                    "copy instruction reads outside base at {opcode_pos}"
                )));
            }
            output.extend_from_slice(&base[offset..offset + length]);
            instructions.push(DeltaInstruction {
                start: opcode_pos,
                end: pos,
                kind: "copy",
                offset,
                length,
            });
        } else if opcode != 0 {
            let length = opcode as usize;
            if pos.checked_add(length).map_or(true, |end| end > delta.len()) {
                return Err(Error::Corrupt(format!(
                    "insert instruction reads outside delta at {opcode_pos}"
                )));
            }
            output.extend_from_slice(&delta[pos..pos + length]);
            pos += length;
            instructions.push(DeltaInstruction {
                start: opcode_pos,
                end: pos,
                kind: "insert",
                offset: 0,
                length,
            });
        } else {
            return Err(Error::Corrupt("reserved zero delta opcode".into()));
        }
        if output.len() as u64 > target_size {
            return Err(Error::Corrupt("delta target exceeded while applying".into()));
        }
    }

    if output.len() as u64 != target_size {
        return Err(Error::Corrupt(format!(
            "delta output length {} does not match declared target size {target_size}",
            output.len()
        )));
    }
    if pos != delta.len() {
        return Err(Error::Corrupt("delta data contains trailing bytes".into()));
    }
    Ok(AppliedDelta {
        target_size,
        instructions,
        output,
    })
}

pub fn object_frame(type_name: &str, body: &[u8]) -> Vec<u8> {
    let mut frame = format!("{} {}\0", type_name, body.len()).into_bytes();
    frame.extend_from_slice(body);
    frame
}
