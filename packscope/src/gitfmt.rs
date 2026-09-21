//! Low-level Git object format helpers: ids, type names, size varints,
//! and bounded zlib decompression with exact stream-boundary detection.

use anyhow::{bail, Result};
use serde::Serialize;
use sha1::{Digest, Sha1};

pub const OID_LEN: usize = 20;

/// Object types used inside packfiles (bits 6..4 of the first header byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum ObjType {
    Commit = 1,
    Tree = 2,
    Blob = 3,
    Tag = 4,
    OfsDelta = 6,
    RefDelta = 7,
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

    pub fn is_delta(self) -> bool {
        matches!(self, ObjType::OfsDelta | ObjType::RefDelta)
    }

    pub fn base_type(self) -> Option<ObjType> {
        match self {
            ObjType::Commit | ObjType::Tree | ObjType::Blob | ObjType::Tag => Some(self),
            _ => None,
        }
    }
}

/// Parse a loose-object type name into a pack object type.
pub fn type_from_name(name: &str) -> Option<ObjType> {
    match name {
        "commit" => Some(ObjType::Commit),
        "tree" => Some(ObjType::Tree),
        "blob" => Some(ObjType::Blob),
        "tag" => Some(ObjType::Tag),
        _ => None,
    }
}

/// Compute the Git object id (`sha1("<type> <len>\0<content>")`) of raw content.
pub fn git_oid(kind: ObjType, content: &[u8]) -> [u8; OID_LEN] {
    let header = format!("{} {}\0", kind.name(), content.len());
    let mut hasher = Sha1::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hasher.finalize().into()
}

/// Compute the SHA-1 over arbitrary bytes (used for content fingerprints).
pub fn sha1_bytes(data: &[u8]) -> [u8; OID_LEN] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Parse the little-endian "n-byte size" used in pack entry headers.
/// Returns `(value, bytes_consumed)`.
pub fn parse_size_encoding(data: &[u8]) -> Result<(u64, usize)> {
    let mut shift = 0u32;
    let mut value: u64 = 0;
    for (i, &b) in data.iter().enumerate() {
        if shift >= 64 {
            bail!("size encoding overflow");
        }
        value |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return Ok((value, i + 1));
        }
    }
    bail!("truncated size encoding")
}

/// Parse an ofs-delta negative-offset encoding. Returns `(distance, bytes_consumed)`.
pub fn parse_ofs_delta_offset(data: &[u8]) -> Result<(u64, usize)> {
    let mut used = 0usize;
    if data.is_empty() {
        bail!("truncated ofs-delta offset");
    }
    let mut c = data[0] as u64;
    used += 1;
    let mut offset = c & 0x7f;
    while c & 0x80 != 0 {
        if used >= data.len() {
            bail!("truncated ofs-delta offset");
        }
        c = data[used] as u64;
        used += 1;
        offset = ((offset + 1) << 7) | (c & 0x7f);
    }
    Ok((offset, used))
}

/// Encode a size/offset in the same little-endian continuation-bit form.
pub fn encode_size(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let mut first = true;
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if !first {
            byte |= 0x80;
        }
        first = false;
        out.push(byte);
        if value == 0 {
            break;
        }
    }
    out
}

/// Outcome of a bounded zlib inflate: decompressed bytes plus the exact
/// number of *compressed* bytes consumed (the zlib stream boundary).
#[derive(Debug, Clone)]
pub struct InflateOutcome {
    pub data: Vec<u8>,
    pub consumed: usize,
}

/// Inflate exactly one zlib stream starting at `input[0..]`.
///
/// * `max_out` bounds decompressed output (resource guard).
/// * Returns the consumed byte count so the caller can locate the next entry.
/// * Detects truncated streams and trailing garbage-less over-consumption.
pub fn inflate_zlib(input: &[u8], max_out: usize) -> Result<InflateOutcome> {
    use flate2::Decompress;
    let mut decomp = Decompress::new(true);
    let mut out = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        if out.len() > max_out {
            bail!("decompressed output exceeds budget of {} bytes", max_out);
        }
        let before_in = decomp.total_in();
        let before_out = decomp.total_out();
        let res = decomp.decompress(input, &mut tmp, flate2::FlushDecompress::None);
        let got = (decomp.total_out() - before_out) as usize;
        out.extend_from_slice(&tmp[..got]);
        match res {
            Ok(flate2::Status::Ok) => {
                if decomp.total_in() == before_in && got == 0 {
                    bail!("zlib stream made no progress (truncated)");
                }
            }
            Ok(flate2::Status::StreamEnd) => break,
            Ok(flate2::Status::BufError) => {
                bail!("unexpected zlib buffer error");
            }
            Err(e) => bail!("zlib decompression error: {e}"),
        }
    }
    Ok(InflateOutcome {
        data: out,
        consumed: decomp.total_in() as usize,
    })
}

/// Deflate data as a zlib stream (used by the synthetic pack test builder).
pub fn deflate_zlib(data: &[u8]) -> Vec<u8> {
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    enc.write_all(data).expect("zlib encode");
    enc.finish().expect("zlib finish")
}

/// Parse the header of a loose object body: returns type and payload.
pub fn parse_loose_body(body: &[u8]) -> Result<(ObjType, &[u8])> {
    let nul = body
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| anyhow::anyhow!("loose object missing NUL header terminator"))?;
    let header = std::str::from_utf8(&body[..nul])?;
    let mut parts = header.split(' ');
    let tname = parts.next().unwrap_or("");
    let len: usize = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("loose header missing length"))?
        .parse()?;
    let kind = type_from_name(tname)
        .ok_or_else(|| anyhow::anyhow!("unknown loose object type: {tname}"))?;
    let payload = &body[nul + 1..];
    if payload.len() != len {
        bail!(
            "loose object length mismatch: header says {len}, body has {}",
            payload.len()
        );
    }
    Ok((kind, payload))
}

/// A short human preview of object content for the UI.
pub fn preview_content(kind: ObjType, content: &[u8], limit: usize) -> String {
    match kind {
        ObjType::Commit | ObjType::Tag => {
            let text = String::from_utf8_lossy(content);
            truncate_preview(&text, limit)
        }
        ObjType::Blob => {
            if content.is_ascii() {
                let text = String::from_utf8_lossy(content);
                truncate_preview(&text, limit)
            } else {
                binary_preview(content, limit)
            }
        }
        ObjType::Tree => preview_tree(content),
        ObjType::OfsDelta | ObjType::RefDelta => binary_preview(content, limit),
    }
}

fn truncate_preview(text: &str, limit: usize) -> String {
    let mut s: String = text.chars().take(limit).collect();
    if text.chars().count() > limit {
        s.push('…');
    }
    s
}

fn binary_preview(data: &[u8], limit: usize) -> String {
    let mut s = String::from("hex: ");
    for byte in data.iter().take(limit) {
        s.push_str(&hex::encode([*byte]));
        s.push(' ');
    }
    if data.len() > limit {
        s.push('…');
    }
    s
}

/// Parse a tree object into a small textual preview.
pub fn preview_tree(content: &[u8]) -> String {
    let mut lines = Vec::new();
    let mut pos = 0;
    while pos < content.len() {
        let sp = match content[pos..].iter().position(|&b| b == b' ') {
            Some(p) => pos + p,
            None => break,
        };
        let mode = std::str::from_utf8(&content[pos..sp]).unwrap_or("?");
        let nul = match content[sp + 1..].iter().position(|&b| b == 0) {
            Some(p) => sp + 1 + p,
            None => break,
        };
        let name = std::str::from_utf8(&content[sp + 1..nul]).unwrap_or("?");
        if nul + OID_LEN >= content.len() {
            break;
        }
        let oid = hex::encode(&content[nul + 1..nul + 1 + OID_LEN]);
        lines.push(format!("{mode:>6} {name} {oid}"));
        pos = nul + 1 + OID_LEN;
    }
    lines.join("\n")
}
