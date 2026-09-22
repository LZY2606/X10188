//! Low level Git object/pack primitives. Pure Rust, no git binary, no git2.

use flate2::Decompress;
use sha1::{Digest, Sha1};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Commit,
    Tree,
    Blob,
    Tag,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Commit => "commit",
            Kind::Tree => "tree",
            Kind::Blob => "blob",
            Kind::Tag => "tag",
        }
    }

    pub fn from_code(code: u8) -> Option<Kind> {
        Some(match code {
            1 => Kind::Commit,
            2 => Kind::Tree,
            3 => Kind::Blob,
            4 => Kind::Tag,
            _ => return None,
        })
    }

    pub fn header(self, len: usize) -> Vec<u8> {
        let mut v = self.name().as_bytes().to_vec();
        v.push(b' ');
        v.extend_from_slice(len.to_string().as_bytes());
        v.push(0);
        v.extend(std::iter::empty::<u8>());
        v
    }
}

/// SHA-1 of `"<type> <len>\0<content>"`, returned as a 40-char hex oid.
pub fn git_oid(kind: Kind, content: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(kind.name().as_bytes());
    h.update(b" ");
    h.update(content.len().to_string().as_bytes());
    h.update([0u8]);
    h.update(content);
    hex::encode(h.finalize())
}

pub fn oid_from_bytes(b: &[u8]) -> String {
    hex::encode(b)
}

pub fn oid_to_bytes(oid: &str) -> Option<[u8; 20]> {
    let mut out = [0u8; 20];
    let v = hex::decode(oid).ok()?;
    if v.len() != 20 {
        return None;
    }
    out.copy_from_slice(&v);
    Some(out)
}

/// Git pack "size encoding" (little endian base-128 varint, MSB=continue).
/// Returns `(value, bytes_consumed)`.
pub fn read_size(data: &[u8], mut pos: usize) -> Result<(u64, usize), String> {
    let mut shift = 0u32;
    let mut value: u64 = 0;
    let start = pos;
    loop {
        if pos >= data.len() {
            return Err("size encoding truncated".into());
        }
        let b = data[pos];
        pos += 1;
        value |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err("size encoding overflow".into());
        }
    }
    Ok((value, pos - start))
}

/// Big endian base-128 varint used by ofs-delta negative offsets.
/// First byte contributes its low 7 bits plus one (the "+1" fold);
/// every continuation byte shifts in 7 more bits.
pub fn read_ofs_delta_offset(data: &[u8], mut pos: usize) -> Result<(u64, usize), String> {
    let start = pos;
    if pos >= data.len() {
        return Err("ofs-delta header truncated".into());
    }
    let mut b = data[pos];
    pos += 1;
    let mut offset = u64::from(b & 0x7f);
    while b & 0x80 != 0 {
        if pos >= data.len() {
            return Err("ofs-delta header truncated".into());
        }
        b = data[pos];
        pos += 1;
        offset = offset
            .checked_add(1)
            .and_then(|o| o.checked_shl(7))
            .ok_or_else(|| "ofs-delta offset overflow".to_string())?;
        offset += u64::from(b & 0x7f);
    }
    Ok((offset, pos - start))
}

/// Parse a pack object header at `pos`.
/// Returns `(type_code, inflated_size, header_len)`.
pub fn read_obj_header(data: &[u8], pos: usize) -> Result<(u8, u64, usize), String> {
    let mut p = pos;
    if p >= data.len() {
        return Err("object header truncated".into());
    }
    let first = data[p];
    let type_code = (first >> 4) & 0x07;
    let mut size = u64::from(first & 0x0f);
    p += 1;
    let mut shift = 4;
    let mut b = first;
    while b & 0x80 != 0 {
        if p >= data.len() {
            return Err("object header truncated".into());
        }
        b = data[p];
        p += 1;
        size |= u64::from(b & 0x7f) << shift;
        shift += 7;
    }
    Ok((type_code, size, p - pos))
}

/// Result of a zlib inflate, with exact byte boundaries inside the container.
#[derive(Clone, Debug)]
pub struct InflateResult {
    pub data: Vec<u8>,
    /// number of compressed bytes consumed from the input slice
    pub consumed: usize,
}

/// Inflate a zlib stream beginning at `data[pos]`.
///
/// `declared_size` is the size advertised by the pack header and is only a hint
/// used for pre-allocation; the actual inflated length is what gets returned,
/// so a lying ("spoofed") size can be detected by the caller.
///
/// `hard_cap` aborts (returning `Err("CAP: ...")`) as soon as more than
/// `hard_cap` output bytes would be produced; this is a safety valve
/// independent of the reconstruction budget.
pub fn inflate_from(
    data: &[u8],
    pos: usize,
    declared_size: u64,
    hard_cap: usize,
) -> Result<InflateResult, String> {
    let mut dec = Decompress::new(true);
    let hint = (declared_size.min(hard_cap as u64) as usize).max(64);
    let mut out: Vec<u8> = Vec::with_capacity(hint.min(1 << 20));
    let feed = 16 * 1024usize;
    let mut next_in = pos;

    loop {
        let end = (next_in + feed).min(data.len());
        if next_in >= end {
            return Err("zlib input exhausted before stream end".into());
        }
        let before_in = dec.total_in();
        let before_out = dec.total_out();
        let mut tmp = [0u8; 16 * 1024];
        let status = dec
            .decompress(&data[next_in..end], &mut tmp, flate2::FlushDecompress::None)
            .map_err(|e| format!("zlib error: {e}"))?;
        let ate = (dec.total_in() - before_in) as usize;
        let produced = (dec.total_out() - before_out) as usize;
        out.extend_from_slice(&tmp[..produced]);
        next_in += ate;
        if out.len() > hard_cap {
            return Err(format!("CAP: inflated payload exceeds {hard_cap} bytes"));
        }
        match status {
            flate2::Status::StreamEnd => {
                // total_in is relative to the very first slice we fed, which
                // started at `pos`; since all slices are contiguous windows of
                // the original buffer this is exactly the compressed length.
                return Ok(InflateResult {
                    data: out,
                    consumed: dec.total_in() as usize,
                });
            }
            flate2::Status::Ok if next_in >= data.len() => {
                return Err("zlib stream truncated at end of input".into());
            }
            flate2::Status::Ok => {}
            flate2::Status::BufError => {
                // output window never filled while input advanced; retry
                if ate == 0 {
                    return Err("zlib made no progress".into());
                }
            }
        }
    }
}

/// A single delta instruction's byte range and semantic, for per-step evidence.
#[derive(Clone, Debug)]
pub struct DeltaInstr {
    /// byte offset range within the *delta instruction stream*
    pub range: (usize, usize),
    pub kind: &'static str,
    pub detail: String,
}

#[derive(Clone, Debug)]
pub struct AppliedDelta {
    pub out: Vec<u8>,
    pub instrs: Vec<DeltaInstr>,
}

/// Apply a git delta to `base`.
///
/// `out_cap` bounds the produced size (per-object / per-chain budget). Returns
/// `Err("CAP: ...")` when the result would exceed the cap, `Err(other)` for a
/// malformed delta.
pub fn apply_delta(base: &[u8], delta: &[u8], out_cap: usize) -> Result<AppliedDelta, String> {
    let mut pos = 0usize;
    let (base_size, n) = read_size(delta, pos)?;
    pos += n;
    if base_size as usize != base.len() {
        return Err(format!(
            "delta base size mismatch: header says {base_size}, base is {}",
            base.len()
        ));
    }
    let (result_size, n) = read_size(delta, pos)?;
    pos += n;
    if result_size as usize > out_cap {
        return Err(format!("CAP: delta result {result_size} exceeds {out_cap}"));
    }
    let mut out = Vec::with_capacity(result_size as usize);
    let mut instrs: Vec<DeltaInstr> = Vec::new();

    while pos < delta.len() {
        let start = pos;
        let op = delta[pos];
        pos += 1;
        if op & 0x80 != 0 {
            // copy from base
            let mut off: usize = 0;
            let mut len: usize = 0;
            for i in 0..4u8 {
                if op & (1 << i) != 0 {
                    if pos >= delta.len() {
                        return Err("copy offset truncated".into());
                    }
                    off |= usize::from(delta[pos]) << (8 * i);
                    pos += 1;
                }
            }
            for i in 0..3u8 {
                if op & (1 << (4 + i)) != 0 {
                    if pos >= delta.len() {
                        return Err("copy length truncated".into());
                    }
                    len |= usize::from(delta[pos]) << (8 * i);
                    pos += 1;
                }
            }
            if len == 0 {
                len = 0x10000;
            }
            if out.len() + len > out_cap {
                return Err(format!("CAP: delta copy pushes output beyond {out_cap}"));
            }
            let end = off.checked_add(len).ok_or("copy offset overflow")?;
            if end > base.len() {
                return Err(format!(
                    "copy out of base bounds: off={off} len={len} base_len={}",
                    base.len()
                ));
            }
            out.extend_from_slice(&base[off..end]);
            instrs.push(DeltaInstr {
                range: (start, pos),
                kind: "copy",
                detail: format!("base[{off}..{end}] -> +{len}"),
            });
        } else if op != 0 {
            // insert literal
            let len = op as usize;
            if pos + len > delta.len() {
                return Err("insert literal truncated".into());
            }
            if out.len() + len > out_cap {
                return Err(format!("CAP: delta insert pushes output beyond {out_cap}"));
            }
            out.extend_from_slice(&delta[pos..pos + len]);
            pos += len;
            instrs.push(DeltaInstr {
                range: (start, pos),
                kind: "insert",
                detail: format!("+{len} literal bytes"),
            });
        } else {
            return Err("delta opcode 0 is reserved".into());
        }
    }

    if out.len() as u64 != result_size {
        return Err(format!(
            "delta result size mismatch: produced {}, header {result_size}",
            out.len()
        ));
    }
    Ok(AppliedDelta { out, instrs })
}

/// Git CRC32 for pack trailers (same polynomial as zlib crc32).
pub fn crc32(data: &[u8]) -> u32 {
    // Standard CRC-32 (IEEE 802.3), matching git's crc32 used in .idx v2.
    let mut crc: u32 = 0xffff_ffff;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Short human preview of object content, with a hex tail for binary.
pub fn preview(data: &[u8], limit: usize) -> String {
    let head: Vec<u8> = data.iter().take(limit).copied().collect();
    let printable = head
        .iter()
        .all(|&b| b == b'\n' || b == b'\t' || b == b'\r' || (0x20..=0x7e).contains(&b));
    if printable {
        String::from_utf8_lossy(&head).replace('\0', "\\0")
    } else {
        let mut s = String::from("0x");
        for b in head.iter().take(limit / 2) {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}
