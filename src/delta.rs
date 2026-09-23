//! Git delta instruction decoding and application.

use crate::error::{ParseError, ParseResult};

#[derive(Clone, Debug)]
pub enum DeltaCmd {
    /// Copy `len` bytes from base starting at `offset`.
    Copy { offset: u64, len: u64 },
    /// Insert literal bytes.
    Insert { data: Vec<u8> },
}

#[derive(Clone, Debug)]
pub struct DeltaScript {
    pub base_size: u64,
    pub result_size: u64,
    pub commands: Vec<DeltaCmd>,
    /// Byte ranges of each command within the delta buffer (after the two
    /// size varints), parallel to `commands`.
    pub cmd_ranges: Vec<(usize, usize)>,
    pub header_len: usize,
}

fn read_varint(buf: &[u8], pos: &mut usize) -> ParseResult<u64> {
    let mut out: u64 = 0;
    let mut shift = 0u32;
    loop {
        if *pos >= buf.len() {
            return Err(ParseError::BadDelta("varint truncated".into()));
        }
        let b = buf[*pos];
        *pos += 1;
        out |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            break;
        }
        if shift > 63 {
            return Err(ParseError::BadDelta("varint too long".into()));
        }
    }
    Ok(out)
}

pub fn parse_delta(buf: &[u8]) -> ParseResult<DeltaScript> {
    let mut pos = 0usize;
    let base_size = read_varint(buf, &mut pos)?;
    let result_size = read_varint(buf, &mut pos)?;
    let header_len = pos;
    let mut commands = Vec::new();
    let mut cmd_ranges = Vec::new();
    while pos < buf.len() {
        let start = pos;
        let op = buf[pos];
        pos += 1;
        if op & 0x80 != 0 {
            let mut offset: u64 = 0;
            let mut len: u64 = 0;
            for i in 0..4 {
                if op & (1 << i) != 0 {
                    if pos >= buf.len() {
                        return Err(ParseError::BadDelta("copy offset truncated".into()));
                    }
                    offset |= (buf[pos] as u64) << (8 * i);
                    pos += 1;
                }
            }
            for i in 0..3 {
                if op & (0x10 << i) != 0 {
                    if pos >= buf.len() {
                        return Err(ParseError::BadDelta("copy size truncated".into()));
                    }
                    len |= (buf[pos] as u64) << (8 * i);
                    pos += 1;
                }
            }
            if len == 0 {
                len = 0x10000;
            }
            commands.push(DeltaCmd::Copy { offset, len });
        } else if op != 0 {
            let n = op as usize;
            if pos + n > buf.len() {
                return Err(ParseError::BadDelta(format!(
                    "insert of {n} bytes overruns delta ({} left)",
                    buf.len() - pos
                )));
            }
            commands.push(DeltaCmd::Insert {
                data: buf[pos..pos + n].to_vec(),
            });
            pos += n;
        } else {
            return Err(ParseError::BadDelta("opcode 0 is reserved".into()));
        }
        cmd_ranges.push((start, pos));
    }
    Ok(DeltaScript {
        base_size,
        result_size,
        commands,
        cmd_ranges,
        header_len,
    })
}

/// Apply a parsed delta to `base`, verifying base size, copy bounds and the
/// declared result size.
pub fn apply_delta(script: &DeltaScript, base: &[u8]) -> ParseResult<Vec<u8>> {
    if base.len() as u64 != script.base_size {
        return Err(ParseError::SizeSpoof {
            declared: script.base_size,
            actual: base.len() as u64,
        });
    }
    let mut out = Vec::with_capacity(script.result_size.min(1 << 26) as usize);
    for cmd in &script.commands {
        match cmd {
            DeltaCmd::Copy { offset, len } => {
                let start = *offset as usize;
                let end = start
                    .checked_add(*len as usize)
                    .ok_or_else(|| ParseError::BadDelta("copy range overflow".into()))?;
                if end > base.len() {
                    return Err(ParseError::BadDelta(format!(
                        "copy [{offset}, +{len}) exceeds base of {} bytes",
                        base.len()
                    )));
                }
                out.extend_from_slice(&base[start..end]);
            }
            DeltaCmd::Insert { data } => out.extend_from_slice(data),
        }
    }
    if out.len() as u64 != script.result_size {
        return Err(ParseError::SizeSpoof {
            declared: script.result_size,
            actual: out.len() as u64,
        });
    }
    Ok(out)
}
