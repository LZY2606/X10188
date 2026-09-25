//! Git object model helpers: type names, object id computation, zlib boundary.

use flate2::{Decompress, FlushDecompress, Status};
use sha1::{Digest, Sha1};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

    pub fn pack_code(self) -> u8 {
        match self {
            ObjType::Commit => 1,
            ObjType::Tree => 2,
            ObjType::Blob => 3,
            ObjType::Tag => 4,
            ObjType::OfsDelta => 6,
            ObjType::RefDelta => 7,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            ObjType::Commit => "commit",
            ObjType::Tree => "tree",
            ObjType::Blob => "blob",
            ObjType::Tag => "tag",
            ObjType::OfsDelta => "ofs_delta",
            ObjType::RefDelta => "ref_delta",
        }
    }

    pub fn from_name(s: &str) -> Option<ObjType> {
        match s {
            "commit" => Some(ObjType::Commit),
            "tree" => Some(ObjType::Tree),
            "blob" => Some(ObjType::Blob),
            "tag" => Some(ObjType::Tag),
            "ofs_delta" => Some(ObjType::OfsDelta),
            "ref_delta" => Some(ObjType::RefDelta),
            _ => None,
        }
    }

    pub fn is_delta(self) -> bool {
        matches!(self, ObjType::OfsDelta | ObjType::RefDelta)
    }
}

/// Compute the Git object id (SHA-1 over "<type> <len>\0<content>").
pub fn object_id(obj_type: ObjType, content: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(obj_type.name().as_bytes());
    h.update(b" ");
    h.update(content.len().to_string().as_bytes());
    h.update(b"\0");
    h.update(content);
    hex::encode(h.finalize())
}

/// Decompress a single zlib stream starting at `data[0]`.
/// Returns (decompressed bytes, compressed length consumed).
/// The compressed length is the exact zlib stream boundary, which lets the
/// caller locate the next pack entry without any trailing-byte guessing.
pub fn zlib_decompress_bounded(data: &[u8]) -> Result<(Vec<u8>, usize), String> {
    let mut d = Decompress::new(true);
    let mut out = Vec::with_capacity(data.len().max(64));
    // Feed input in chunks so we never hand the decoder bytes past the end
    // of the stream; total_in() then gives the exact boundary.
    let mut in_pos = 0usize;
    loop {
        let before_in = d.total_in() as usize;
        let before_out = d.total_out() as usize;
        let chunk_end = (in_pos + 4096).min(data.len());
        let status = d
            .decompress_vec(&data[in_pos..chunk_end], &mut out, FlushDecompress::None)
            .map_err(|e| format!("zlib decode error: {e}"))?;
        let consumed = (d.total_in() as usize) - before_in;
        in_pos += consumed;
        let produced = (d.total_out() as usize) - before_out;
        match status {
            Status::StreamEnd => return Ok((out, d.total_in() as usize)),
            Status::Ok | Status::BufError => {
                if consumed == 0 && produced == 0 {
                    if in_pos >= data.len() {
                        return Err(format!(
                            "zlib stream truncated after {} input bytes",
                            data.len()
                        ));
                    }
                    // No progress possible with current buffer state; grow output.
                    if out.capacity() == out.len() {
                        out.reserve(4096);
                    }
                }
            }
        }
    }
}

/// Decompress a whole buffer that must contain exactly one zlib stream.
pub fn zlib_decompress_all(data: &[u8]) -> Result<Vec<u8>, String> {
    let (out, used) = zlib_decompress_bounded(data)?;
    if used != data.len() {
        return Err(format!(
            "trailing {} bytes after zlib stream",
            data.len() - used
        ));
    }
    Ok(out)
}

/// SHA-1 hex of raw bytes (used for pack trailer verification).
pub fn sha1_hex(data: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// SHA-256 hex digest, used as the import content digest for sources.
pub fn content_digest(data: &[u8]) -> String {
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}
