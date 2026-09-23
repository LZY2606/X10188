//! Low level Git object/zlib primitives (no system git involved).

use miniz_oxide::inflate::core::{decompress, DecompressorOxide, TINFLFlush, TINFLStatus};
use sha1::{Digest, Sha1};

/// Canonical Git object type names used in loose/framed objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjType {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
}

impl ObjType {
    pub fn from_pack_code(code: u8) -> Option<ObjType> {
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

    pub fn pack_code(self) -> Option<u8> {
        match self {
            ObjType::Commit => Some(1),
            ObjType::Tree => Some(2),
            ObjType::Blob => Some(3),
            ObjType::Tag => Some(4),
            ObjType::OfsDelta => Some(6),
            ObjType::RefDelta => Some(7),
        }
    }

    pub fn is_delta(self) -> bool {
        matches!(self, ObjType::OfsDelta | ObjType::RefDelta)
    }

    pub fn name(self) -> &'static str {
        match self {
            ObjType::Commit => "commit",
            ObjType::Tree => "tree",
            ObjType::Blob => "blob",
            ObjType::Tag => "tag",
            ObjType::OfsDelta => "ofs-delta",
            ObjType::RefDelta => "ref-delta",
        }
    }

    pub fn from_name(name: &str) -> Option<ObjType> {
        match name {
            "commit" => Some(ObjType::Commit),
            "tree" => Some(ObjType::Tree),
            "blob" => Some(ObjType::Blob),
            "tag" => Some(ObjType::Tag),
            _ => None,
        }
    }
}

/// Read the pack entry header variable length type/size encoding.
/// Returns (type, declared inflated size, header length in bytes).
pub fn read_pack_header_size(buf: &[u8], start: usize) -> Result<(ObjType, u64, usize), String> {
    let mut p = start;
    let first = *buf.get(p).ok_or_else(|| "truncated pack entry header".to_string())?;
    p += 1;
    let code = (first >> 4) & 0x07;
    let typ = ObjType::from_pack_code(code)
        .ok_or_else(|| format!("invalid pack object type code {} at offset {}", code, start))?;
    let mut size = (first & 0x0f) as u64;
    let mut shift = 4u32;
    let mut b = first;
    while b & 0x80 != 0 {
        b = *buf.get(p).ok_or_else(|| "truncated pack entry size varint".to_string())?;
        p += 1;
        size |= ((b & 0x7f) as u64) << shift;
        shift += 7;
    }
    Ok((typ, size, p - start))
}

/// Read the ofs-delta negative-offset varint.
pub fn read_ofs_delta(buf: &[u8], start: usize) -> Result<(u64, usize), String> {
    let mut p = start;
    let mut b = *buf.get(p).ok_or_else(|| "truncated ofs-delta offset".to_string())?;
    p += 1;
    let mut ofs = (b & 0x7f) as u64;
    while b & 0x80 != 0 {
        b = *buf.get(p).ok_or_else(|| "truncated ofs-delta offset varint".to_string())?;
        p += 1;
        ofs = ((ofs + 1) << 7) | (b & 0x7f) as u64;
    }
    Ok((ofs, p - start))
}

/// Little-endian-base-128 size varint used by loose object headers and deltas.
pub fn read_le_varint(buf: &[u8], start: usize) -> Result<(u64, usize), String> {
    let mut p = start;
    let mut size = 0u64;
    let mut shift = 0u32;
    loop {
        let b = *buf.get(p).ok_or_else(|| "truncated size varint".to_string())?;
        p += 1;
        size |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            break;
        }
        if shift > 63 {
            return Err("size varint too long".to_string());
        }
    }
    Ok((size, p - start))
}

pub fn write_le_varint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let mut b = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            b |= 0x80;
        }
        out.push(b);
        if value == 0 {
            break;
        }
    }
}

/// Write the pack entry type/size header (not including delta base descriptors).
pub fn write_pack_header_size(typ: ObjType, size: u64, out: &mut Vec<u8>) {
    let code = typ.pack_code().expect("delta/base type");
    let mut first = (code << 4) | ((size as u8) & 0x0f);
    let mut rest = size >> 4;
    if rest != 0 {
        first |= 0x80;
    }
    out.push(first);
    while rest != 0 {
        let mut b = (rest as u8) & 0x7f;
        rest >>= 7;
        if rest != 0 {
            b |= 0x80;
        }
        out.push(b);
    }
}

pub fn write_ofs_delta(negative: u64, out: &mut Vec<u8>) {
    let mut bytes = vec![negative as u8 & 0x7f];
    let mut v = negative >> 7;
    while v != 0 {
        bytes.push((v as u8 & 0x7f) | 0x80);
        v >>= 7;
    }
    bytes.reverse();
    if bytes.len() > 1 {
        for b in bytes.iter_mut().take(bytes.len() - 1) {
            *b |= 0x80;
        }
    }
    out.extend_from_slice(&bytes);
}

pub struct InflateOutcome {
    pub data: Vec<u8>,
    /// Number of input bytes consumed, including the adler32 trailer.
    pub input_consumed: usize,
}

/// Inflate a zlib stream starting at `buf[start]`, stopping exactly at the
/// stream boundary so callers keep the raw pack offset of the next entry.
///
/// `declared_size` (when known) is enforced while inflating so that a stream
/// whose real payload is larger than the header promise ("size spoof") is
/// detected mid-decompression without unbounded allocation. `hard_cap` always
/// bounds allocation. Declared sizes above `hard_cap` return
/// [`InflateError::OverCap`] without any decompression.
pub fn inflate_zlib_bounded(
    buf: &[u8],
    start: usize,
    declared_size: Option<u64>,
    hard_cap: usize,
) -> Result<InflateOutcome, InflateError> {
    if let Some(d) = declared_size {
        if d as usize > hard_cap {
            return Err(InflateError::OverCap(d));
        }
    }
    let cap_limit = declared_size.map(|d| d as usize).unwrap_or(hard_cap);
    let mut decomp = DecompressorOxide::new();
    let mut out: Vec<u8> = Vec::new();
    let mut pos = start;
    loop {
        if pos >= buf.len() {
            return Err(InflateError::Msg("zlib stream truncated: no more input".to_string()));
        }
        if out.len() >= cap_limit {
            // Buffer already at the promised size: probe whether the stream
            // actually ends here. If it needs more output, that is a spoof.
            let (status, consumed, _written) =
                decompress(&mut decomp, &buf[pos..], &mut [], TINFLFlush::Finish);
            pos += consumed;
            match status {
                TINFLStatus::Done => {
                    if let Some(d) = declared_size {
                        if out.len() as u64 != d {
                            return Err(InflateError::Msg(format!(
                                "size spoof: declared {} but produced {}",
                                d,
                                out.len()
                            )));
                        }
                    }
                    return Ok(InflateOutcome { data: out, input_consumed: pos });
                }
                TINFLStatus::NeedsMoreOutput => {
                    return Err(match declared_size {
                        Some(d) => InflateError::Msg(format!(
                            "size spoof: inflated payload exceeds declared size {}",
                            d
                        )),
                        None => InflateError::OverCap(cap_limit as u64 + 1),
                    });
                }
                TINFLStatus::NeedsMoreInput => {
                    return Err(InflateError::Msg("zlib stream truncated".to_string()));
                }
                TINFLStatus::FailedCannotMakeProgress | TINFLStatus::BadParam => {
                    return Err(InflateError::Msg("invalid zlib data".to_string()));
                }
            }
        }
        let grow = 4096usize.min(cap_limit - out.len()).max(1);
        let old_len = out.len();
        out.resize(old_len + grow, 0);
        let (status, consumed, written) =
            decompress(&mut decomp, &buf[pos..], &mut out[old_len..], TINFLFlush::None);
        pos += consumed;
        out.truncate(old_len + written);
        match status {
            TINFLStatus::Done => {
                if let Some(d) = declared_size {
                    if out.len() as u64 != d {
                        return Err(InflateError::Msg(format!(
                            "size spoof: declared {} but produced {}",
                            d,
                            out.len()
                        )));
                    }
                }
                return Ok(InflateOutcome { data: out, input_consumed: pos });
            }
            TINFLStatus::Okay | TINFLStatus::NeedsMoreOutput => {}
            TINFLStatus::NeedsMoreInput => {
                if written == 0 && consumed == 0 {
                    return Err(InflateError::Msg("zlib stream truncated".to_string()));
                }
            }
            TINFLStatus::FailedCannotMakeProgress | TINFLStatus::BadParam => {
                return Err(InflateError::Msg("invalid zlib data".to_string()));
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum InflateError {
    /// Declared (or discovered) payload exceeds the caller's hard budget.
    OverCap(u64),
    Msg(String),
}

impl InflateError {
    pub fn message(&self) -> String {
        match self {
            InflateError::OverCap(n) => format!("payload size {} exceeds budget", n),
            InflateError::Msg(s) => s.clone(),
        }
    }
}

#[allow(dead_code)]
fn size_spoof_message(declared: Option<u64>, hard_cap: usize) -> String {
    match declared {
        Some(d) => format!(
            "size spoof: inflated payload exceeds declared size {} (hard cap {})",
            d, hard_cap
        ),
        None => format!("inflated payload exceeds hard cap {}", hard_cap),
    }
}

/// Deflate raw bytes to a zlib stream (used by the self contained test packer).
pub fn deflate_zlib(data: &[u8]) -> Vec<u8> {
    use miniz_oxide::deflate::compress_to_vec_zlib;
    compress_to_vec_zlib(data, 6)
}

/// Compute the Git object id of `raw` framed as `<type> <len>\0<raw>`.
pub fn git_object_id(typ: ObjType, raw: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(typ.name().as_bytes());
    h.update(b" ");
    h.update(raw.len().to_string().as_bytes());
    h.update([0u8]);
    h.update(raw);
    h.finalize().into()
}

/// Parse `<type> <len>\0<data>` framing of a loose object payload.
pub fn parse_framed(input: &[u8]) -> Result<(ObjType, Vec<u8>), String> {
    let nul = input
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| "loose object missing NUL framing".to_string())?;
    let header = std::str::from_utf8(&input[..nul]).map_err(|e| e.to_string())?;
    let (name, len_str) = header
        .split_once(' ')
        .ok_or_else(|| "loose object header malformed".to_string())?;
    let typ = ObjType::from_name(name).ok_or_else(|| format!("unknown type {}", name))?;
    let declared: usize = len_str
        .parse()
        .map_err(|_| "loose object length not a number".to_string())?;
    let data = input[nul + 1..].to_vec();
    if data.len() != declared {
        return Err(format!(
            "loose object length spoof: header says {} but payload is {}",
            declared,
            data.len()
        ));
    }
    Ok((typ, data))
}

pub fn hex20(s: &str) -> Option<[u8; 20]> {
    if s.len() != 40 || !s.bytes().all(|b| b.is_ascii_hexdigest()) {
        return None;
    }
    let mut out = [0u8; 20];
    for i in 0..20 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

pub fn hex_sha(id: &[u8]) -> String {
    hex::encode(id)
}
