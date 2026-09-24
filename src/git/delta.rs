//! Git delta (fiddly) parsing and application, with per-instruction tracing.

#[derive(Clone, Debug)]
pub enum Instr {
    Copy {
        /// Byte range of this instruction inside the delta blob.
        delta_pos: usize,
        delta_len: usize,
        src_off: usize,
        src_len: usize,
        dst_off: usize,
        dst_len: usize,
    },
    Insert {
        delta_pos: usize,
        delta_len: usize,
        dst_off: usize,
        dst_len: usize,
    },
}

#[derive(Clone, Debug)]
pub struct DeltaTrace {
    pub declared_base_size: usize,
    pub declared_result_size: usize,
    pub actual_base_len: usize,
    pub result_len: usize,
    pub instrs: Vec<Instr>,
}

#[derive(Debug)]
pub enum DeltaError {
    TruncatedVarint,
    BadCommand(u8, usize),
    CopyOutOfBounds { src_off: usize, src_len: usize, base_len: usize },
    InsertOutOfBounds { delta_pos: usize, take: usize, avail: usize },
    SizeMismatch { declared: usize, actual: usize },
    BaseSizeMismatch { declared: usize, actual: usize },
}

impl std::fmt::Display for DeltaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeltaError::TruncatedVarint => write!(f, "truncated size varint in delta"),
            DeltaError::BadCommand(c, p) => write!(f, "reserved/unknown delta command 0x{:02x} at {}", c, p),
            DeltaError::CopyOutOfBounds { src_off, src_len, base_len } => write!(
                f,
                "copy out of bounds: base[{}..{}] but base len {}",
                src_off,
                src_off + src_len,
                base_len
            ),
            DeltaError::InsertOutOfBounds { delta_pos, take, avail } => write!(
                f,
                "insert at {} asks for {} literal bytes but only {} remain",
                delta_pos, take, avail
            ),
            DeltaError::SizeMismatch { declared, actual } => {
                write!(f, "delta result size {} != assembled output length {}", declared, actual)
            }
            DeltaError::BaseSizeMismatch { declared, actual } => {
                write!(f, "delta base size {} != actual base length {}", declared, actual)
            }
        }
    }
}

impl std::error::Error for DeltaError {}

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn varint(&mut self) -> Result<usize, DeltaError> {
        let mut shift = 0u32;
        let mut val = 0usize;
        loop {
            if self.pos >= self.b.len() {
                return Err(DeltaError::TruncatedVarint);
            }
            let c = self.b[self.pos];
            self.pos += 1;
            val |= ((c & 0x7f) as usize) << shift;
            if c & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift > 28 {
                return Err(DeltaError::TruncatedVarint);
            }
        }
        Ok(val)
    }
    fn need(&self, n: usize) -> Result<(), DeltaError> {
        self.pos
            .checked_add(n)
            .filter(|e| *e <= self.b.len())
            .map(|_| ())
            .ok_or(DeltaError::TruncatedVarint)
    }
}

/// Apply `delta` to `base`, validating every bound and recording the byte
/// ranges each instruction touches in base, delta and output.
pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<(Vec<u8>, DeltaTrace), DeltaError> {
    let mut r = Reader { b: delta, pos: 0 };
    let declared_base_size = r.varint()?;
    let declared_result_size = r.varint()?;
    if declared_base_size != base.len() {
        return Err(DeltaError::BaseSizeMismatch {
            declared: declared_base_size,
            actual: base.len(),
        });
    }

    let mut out: Vec<u8> = Vec::with_capacity(declared_result_size.min(1 << 24));
    let mut instrs: Vec<Instr> = Vec::new();

    while r.pos < delta.len() {
        let cmd_pos = r.pos;
        let op = delta[r.pos];
        r.pos += 1;
        if op & 0x80 != 0 {
            let mut cp_off: u32 = 0;
            let mut cp_size: u32 = 0;
            for i in 0..4 {
                if op & (1 << i) != 0 {
                    r.need(1)?;
                    cp_off |= (delta[r.pos] as u32) << (8 * i);
                    r.pos += 1;
                }
            }
            for i in 0..3 {
                if op & (1 << (4 + i)) != 0 {
                    r.need(1)?;
                    cp_size |= (delta[r.pos] as u32) << (8 * i);
                    r.pos += 1;
                }
            }
            if cp_size == 0 {
                cp_size = 0x10000;
            }
            let src_off = cp_off as usize;
            let src_len = cp_size as usize;
            if src_off.checked_add(src_len).map_or(true, |e| e > base.len()) {
                return Err(DeltaError::CopyOutOfBounds {
                    src_off,
                    src_len,
                    base_len: base.len(),
                });
            }
            let dst_off = out.len();
            if dst_off.checked_add(src_len).map_or(true, |e| e > declared_result_size) {
                return Err(DeltaError::SizeMismatch {
                    declared: declared_result_size,
                    actual: dst_off + src_len,
                });
            }
            out.extend_from_slice(&base[src_off..src_off + src_len]);
            instrs.push(Instr::Copy {
                delta_pos: cmd_pos,
                delta_len: r.pos - cmd_pos,
                src_off,
                src_len,
                dst_off,
                dst_len: src_len,
            });
        } else if op != 0 {
            let take = op as usize;
            if r.pos + take > delta.len() {
                return Err(DeltaError::InsertOutOfBounds {
                    delta_pos: cmd_pos,
                    take,
                    avail: delta.len() - r.pos,
                });
            }
            let dst_off = out.len();
            if dst_off + take > declared_result_size {
                return Err(DeltaError::SizeMismatch {
                    declared: declared_result_size,
                    actual: dst_off + take,
                });
            }
            out.extend_from_slice(&delta[r.pos..r.pos + take]);
            r.pos += take;
            instrs.push(Instr::Insert {
                delta_pos: cmd_pos,
                delta_len: r.pos - cmd_pos,
                dst_off,
                dst_len: take,
            });
        } else {
            return Err(DeltaError::BadCommand(0, cmd_pos));
        }
    }

    if out.len() != declared_result_size {
        return Err(DeltaError::SizeMismatch {
            declared: declared_result_size,
            actual: out.len(),
        });
    }
    Ok((
        out,
        DeltaTrace {
            declared_base_size,
            declared_result_size,
            actual_base_len: base.len(),
            result_len: out.len(),
            instrs,
        },
    ))
}

/// Encode sizes/instructions the same way Git does (used by tests/builders).
pub fn make_delta(base: &[u8], edits: &[(usize, usize, Vec<u8>)]) -> Vec<u8> {
    // edits: (copy_off, copy_len, insert_bytes_after)
    fn varint(mut v: usize) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut b = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                b |= 0x80;
            }
            out.push(b);
            if v == 0 {
                break;
            }
        }
        out
    }
    let mut d = varint(base.len());
    let result_len: usize = edits.iter().map(|(o, l, ins)| l + ins.len()).sum();
    d.extend(varint(result_len));
    for (off, len, ins) in edits {
        if *len > 0 {
            let mut op = 0x80u8;
            let mut args = Vec::new();
            for i in 0..4 {
                let byte = ((*off >> (8 * i)) & 0xff) as u8;
                if byte != 0 {
                    op |= 1 << i;
                    args.push(byte);
                }
            }
            let size = if *len == 0x10000 { 0 } else { *len };
            for i in 0..3 {
                let byte = ((size >> (8 * i)) & 0xff) as u8;
                if byte != 0 {
                    op |= 1 << (4 + i);
                    args.push(byte);
                }
            }
            d.push(op);
            d.extend(args);
        }
        let mut i = 0;
        while i < ins.len() {
            let n = (ins.len() - i).min(127);
            d.push(n as u8);
            d.extend_from_slice(&ins[i..i + n]);
            i += n;
        }
    }
    d
}
