//! Core git object primitives: object id, varints, delta application, zlib boundaries.
use sha1::{Digest, Sha1};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ObjType {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
}

impl ObjType {
    pub fn from_code(code: u8) -> Option<ObjType> {
        match code {
            1 => Some(ObjType::Commit),
            2 => Some(ObjType::Tree),
            3 => Some(ObjType::Blob),
            4 => Some(ObjType::Tag),
            6 => Some(ObjType::OfsDelta),
            7 => Some(ObjType::RefDelta),
            _ => None,
        }
    }
    pub fn code(&self) -> u8 {
        match self {
            ObjType::Commit => 1,
            ObjType::Tree => 2,
            ObjType::Blob => 3,
            ObjType::Tag => 4,
            ObjType::OfsDelta => 6,
            ObjType::RefDelta => 7,
        }
    }
    pub fn is_delta(&self) -> bool {
        matches!(self, ObjType::OfsDelta | ObjType::RefDelta)
    }
    pub fn base_name(&self) -> Option<&'static str> {
        match self {
            ObjType::Commit => Some("commit"),
            ObjType::Tree => Some("tree"),
            ObjType::Blob => Some("blob"),
            ObjType::Tag => Some("tag"),
            _ => None,
        }
    }
    pub fn label(&self) -> &'static str {
        match self {
            ObjType::Commit => "commit",
            ObjType::Tree => "tree",
            ObjType::Blob => "blob",
            ObjType::Tag => "tag",
            ObjType::OfsDelta => "ofs-delta",
            ObjType::RefDelta => "ref-delta",
        }
    }
}

/// Compute the git object id (sha1) for a base object.
pub fn object_id(kind: &str, content: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(format!("{} {}\0", kind, content.len()).as_bytes());
    h.update(content);
    hex::encode(h.finalize())
}

/// Parse a git pack entry header varint: returns (type_code, size, bytes_consumed).
pub fn parse_entry_header(buf: &[u8]) -> Result<(u8, u64, usize), String> {
    if buf.is_empty() {
        return Err("truncated entry header".into());
    }
    let mut byte = buf[0];
    let type_code = (byte >> 4) & 0x7;
    let mut size: u64 = (byte & 0x0f) as u64;
    let mut shift = 4u32;
    let mut pos = 1usize;
    while byte & 0x80 != 0 {
        if pos >= buf.len() {
            return Err("truncated entry header varint".into());
        }
        byte = buf[pos];
        size |= ((byte & 0x7f) as u64) << shift;
        shift += 7;
        pos += 1;
        if shift > 63 {
            return Err("entry size varint overflow".into());
        }
    }
    Ok((type_code, size, pos))
}

/// Parse the ofs-delta negative offset encoding. Returns (distance, bytes_consumed).
pub fn parse_ofs_distance(buf: &[u8]) -> Result<(u64, usize), String> {
    if buf.is_empty() {
        return Err("truncated ofs-delta offset".into());
    }
    let mut pos = 0usize;
    let mut byte = buf[pos];
    pos += 1;
    let mut dist: u64 = (byte & 0x7f) as u64;
    while byte & 0x80 != 0 {
        if pos >= buf.len() {
            return Err("truncated ofs-delta offset".into());
        }
        byte = buf[pos];
        pos += 1;
        dist = ((dist + 1) << 7) | (byte & 0x7f) as u64;
    }
    Ok((dist, pos))
}

/// Parse a little-endian 7-bit group varint (used inside delta data for sizes).
pub fn parse_delta_varint(buf: &[u8], pos: &mut usize) -> Result<u64, String> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    loop {
        if *pos >= buf.len() {
            return Err("truncated delta varint".into());
        }
        let byte = buf[*pos];
        *pos += 1;
        result |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err("delta varint overflow".into());
        }
    }
    Ok(result)
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeltaInstr {
    /// Byte offset of the opcode inside the delta stream.
    pub at: u64,
    pub kind: String, // "copy" | "insert"
    /// Source range in the base object (copy) or delta stream (insert).
    pub src_off: u64,
    pub len: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeltaOutcome {
    pub output: Vec<u8>,
    pub base_size_declared: u64,
    pub target_size_declared: u64,
    pub instrs: Vec<DeltaInstr>,
    /// Byte range of the instruction area inside the delta stream.
    pub instr_range: (u64, u64),
}

/// Apply a git delta. `limit` caps output bytes; exceeding it returns
/// Err("budget:...") and no partial output is exposed to the caller.
pub fn apply_delta(base: &[u8], delta: &[u8], limit: u64) -> Result<DeltaOutcome, String> {
    let mut pos = 0usize;
    let base_size = parse_delta_varint(delta, &mut pos)?;
    if base_size != base.len() as u64 {
        return Err(format!(
            "delta base size mismatch: header says {}, actual base is {}",
            base_size,
            base.len()
        ));
    }
    let target_size = parse_delta_varint(delta, &mut pos)?;
    if target_size > limit {
        return Err(format!(
            "budget: declared target size {} exceeds remaining limit {}",
            target_size, limit
        ));
    }
    let instr_start = pos;
    let mut out: Vec<u8> = Vec::with_capacity(target_size.min(1 << 22) as usize);
    let mut instrs = Vec::new();
    while pos < delta.len() {
        let at = pos;
        let cmd = delta[pos];
        pos += 1;
        if cmd & 0x80 != 0 {
            let mut cp_off: u64 = 0;
            let mut cp_size: u64 = 0;
            for i in 0..4 {
                if cmd & (1 << i) != 0 {
                    if pos >= delta.len() {
                        return Err("truncated copy offset".into());
                    }
                    cp_off |= (delta[pos] as u64) << (8 * i);
                    pos += 1;
                }
            }
            for i in 0..3 {
                if cmd & (0x10 << i) != 0 {
                    if pos >= delta.len() {
                        return Err("truncated copy size".into());
                    }
                    cp_size |= (delta[pos] as u64) << (8 * i);
                    pos += 1;
                }
            }
            if cp_size == 0 {
                cp_size = 0x10000;
            }
            let end = cp_off
                .checked_add(cp_size)
                .ok_or("copy range overflow")?;
            if end > base.len() as u64 {
                return Err(format!(
                    "copy range {}..{} exceeds base size {}",
                    cp_off,
                    end,
                    base.len()
                ));
            }
            out.extend_from_slice(&base[cp_off as usize..end as usize]);
            instrs.push(DeltaInstr {
                at: at as u64,
                kind: "copy".into(),
                src_off: cp_off,
                len: cp_size,
            });
        } else if cmd != 0 {
            let n = cmd as usize;
            if pos + n > delta.len() {
                return Err("truncated insert".into());
            }
            out.extend_from_slice(&delta[pos..pos + n]);
            instrs.push(DeltaInstr {
                at: at as u64,
                kind: "insert".into(),
                src_off: pos as u64,
                len: n as u64,
            });
            pos += n;
        } else {
            return Err("delta opcode 0 is reserved".into());
        }
        if out.len() as u64 > target_size {
            return Err(format!(
                "size deception: instructions produced more than declared target {} bytes",
                target_size
            ));
        }
        if out.len() as u64 > limit {
            return Err("budget: output exceeded remaining expansion budget".into());
        }
    }
    if out.len() as u64 != target_size {
        return Err(format!(
            "size deception: declared target {} but instructions produced {}",
            target_size,
            out.len()
        ));
    }
    Ok(DeltaOutcome {
        output: out,
        base_size_declared: base_size,
        target_size_declared: target_size,
        instrs,
        instr_range: (instr_start as u64, pos as u64),
    })
}

/// Inflate a zlib stream starting at `buf[0]`, reporting how many input bytes
/// the stream consumed (the zlib boundary) and the inflated bytes.
/// Fails if the stream is truncated or corrupt (possibly mid-way).
pub fn inflate_bounded(buf: &[u8], size_cap: u64) -> Result<(Vec<u8>, usize), String> {
    use flate2::{Decompress, FlushDecompress, Status};
    let mut d = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let chunk = 64 * 1024;
    let mut tmp = vec![0u8; chunk];
    loop {
        let before_in = d.total_in();
        let before_out = d.total_out();
        let status = d
            .decompress(&buf[before_in as usize..], &mut tmp, FlushDecompress::None)
            .map_err(|e| format!("zlib error after {} input bytes: {}", before_in, e))?;
        let produced = (d.total_out() - before_out) as usize;
        out.extend_from_slice(&tmp[..produced]);
        if out.len() as u64 > size_cap {
            return Err(format!(
                "size deception: inflated data exceeds cap of {} bytes",
                size_cap
            ));
        }
        match status {
            Status::StreamEnd => {
                return Ok((out, d.total_in() as usize));
            }
            Status::Ok | Status::BufError => {
                if d.total_in() as usize >= buf.len() {
                    return Err(format!(
                        "truncated zlib stream at input offset {}",
                        d.total_in()
                    ));
                }
                if produced == 0 && d.total_in() == before_in {
                    return Err("zlib decoder made no progress".into());
                }
            }
        }
    }
}

/// Inflate an entire buffer that must be exactly one zlib stream.
pub fn inflate_all(buf: &[u8], size_cap: u64) -> Result<Vec<u8>, String> {
    let (out, used) = inflate_bounded(buf, size_cap)?;
    if used != buf.len() {
        return Err(format!(
            "trailing {} bytes after zlib stream",
            buf.len() - used
        ));
    }
    Ok(out)
}
