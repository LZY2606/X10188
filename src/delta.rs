//! Git delta instruction parsing and application.

/// Read a little-endian 7-bit-group varint (delta header encoding).
pub fn read_varint(buf: &[u8], pos: usize) -> Result<(u64, usize), String> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    let mut i = pos;
    loop {
        if i >= buf.len() {
            return Err("delta: truncated varint".to_string());
        }
        let b = buf[i];
        value |= ((b & 0x7f) as u64) << shift;
        i += 1;
        shift += 7;
        if b & 0x80 == 0 {
            break;
        }
        if shift > 63 {
            return Err("delta: varint overflow".to_string());
        }
    }
    Ok((value, i))
}

#[derive(Debug, Clone)]
pub struct DeltaApplied {
    pub output: Vec<u8>,
    /// Byte range (within the delta payload) holding the instruction stream.
    pub instr_offset: u64,
    pub instr_len: u64,
    pub declared_base_size: u64,
    pub declared_target_size: u64,
}

/// Apply a Git delta to `base`. Verifies the declared base/target sizes; a
/// mismatch means the delta header lied about its output size.
pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<DeltaApplied, String> {
    let (base_size, p1) = read_varint(delta, 0)?;
    let (target_size, p2) = read_varint(delta, p1)?;
    if base.len() as u64 != base_size {
        return Err(format!(
            "delta: declared base size {} but base is {} bytes",
            base_size,
            base.len()
        ));
    }
    let mut out: Vec<u8> = Vec::with_capacity(target_size.min(1 << 24) as usize);
    let mut pos = p2;
    while pos < delta.len() {
        let cmd = delta[pos];
        pos += 1;
        if cmd & 0x80 != 0 {
            // copy from base
            let mut offset: u64 = 0;
            let mut size: u64 = 0;
            for i in 0..4 {
                if cmd & (1 << i) != 0 {
                    if pos >= delta.len() {
                        return Err("delta: truncated copy offset".to_string());
                    }
                    offset |= (delta[pos] as u64) << (8 * i);
                    pos += 1;
                }
            }
            for i in 0..3 {
                if cmd & (0x10 << i) != 0 {
                    if pos >= delta.len() {
                        return Err("delta: truncated copy size".to_string());
                    }
                    size |= (delta[pos] as u64) << (8 * i);
                    pos += 1;
                }
            }
            if size == 0 {
                size = 0x10000;
            }
            let end = offset
                .checked_add(size)
                .ok_or("delta: copy range overflow")?;
            if end > base.len() as u64 {
                return Err(format!(
                    "delta: copy [{}..{}) exceeds base of {} bytes",
                    offset,
                    end,
                    base.len()
                ));
            }
            out.extend_from_slice(&base[offset as usize..end as usize]);
        } else if cmd != 0 {
            let n = cmd as usize;
            if pos + n > delta.len() {
                return Err("delta: truncated insert".to_string());
            }
            out.extend_from_slice(&delta[pos..pos + n]);
            pos += n;
        } else {
            return Err("delta: reserved opcode 0".to_string());
        }
        if out.len() as u64 > target_size {
            return Err(format!(
                "delta: output overran declared target size {} (size spoofing)",
                target_size
            ));
        }
    }
    if out.len() as u64 != target_size {
        return Err(format!(
            "delta: declared target size {} but produced {} bytes",
            target_size,
            out.len()
        ));
    }
    Ok(DeltaApplied {
        output: out,
        instr_offset: p2 as u64,
        instr_len: (delta.len() - p2) as u64,
        declared_base_size: base_size,
        declared_target_size: target_size,
    })
}

