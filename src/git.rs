//! Low-level Git primitives: object ids, zlib streams with boundary detection.

use flate2::{Decompress, FlushDecompress, Status};
use sha1::{Digest, Sha1};

pub const OBJ_COMMIT: u8 = 1;
pub const OBJ_TREE: u8 = 2;
pub const OBJ_BLOB: u8 = 3;
pub const OBJ_TAG: u8 = 4;
pub const OBJ_OFS_DELTA: u8 = 6;
pub const OBJ_REF_DELTA: u8 = 7;

pub fn type_name(code: u8) -> &'static str {
    match code {
        OBJ_COMMIT => "commit",
        OBJ_TREE => "tree",
        OBJ_BLOB => "blob",
        OBJ_TAG => "tag",
        OBJ_OFS_DELTA => "ofs-delta",
        OBJ_REF_DELTA => "ref-delta",
        _ => "unknown",
    }
}

pub fn type_code(name: &str) -> Option<u8> {
    match name {
        "commit" => Some(OBJ_COMMIT),
        "tree" => Some(OBJ_TREE),
        "blob" => Some(OBJ_BLOB),
        "tag" => Some(OBJ_TAG),
        _ => None,
    }
}

/// Compute the Git object id (sha1 of "<type> <len>\0<content>").
pub fn object_id(type_code: u8, content: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(type_name(type_code).as_bytes());
    h.update(b" ");
    h.update(content.len().to_string().as_bytes());
    h.update(b"\0");
    h.update(content);
    let out = h.finalize();
    let mut oid = [0u8; 20];
    oid.copy_from_slice(&out);
    oid
}

pub fn oid_hex(oid: &[u8; 20]) -> String {
    hex::encode(oid)
}

pub fn oid_from_hex(s: &str) -> Option<[u8; 20]> {
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != 20 {
        return None;
    }
    let mut oid = [0u8; 20];
    oid.copy_from_slice(&bytes);
    Some(oid)
}

#[derive(Debug, Clone)]
pub struct InflateResult {
    pub data: Vec<u8>,
    /// Bytes of the input consumed by the zlib stream (the zlib boundary).
    pub consumed: u64,
}

#[derive(Debug, Clone)]
pub enum InflateError {
    /// Inflated output exceeded the declared size before the stream ended:
    /// the declared size was a lie discovered mid-decompression.
    SizeSpoofed { declared: u64, actual_so_far: u64 },
    /// Stream ended but the size does not match the declared size.
    SizeMismatch { declared: u64, actual: u64 },
    /// Input ran out before the zlib stream finished.
    Truncated { consumed: u64 },
    /// zlib format error.
    Format(String),
}

impl std::fmt::Display for InflateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InflateError::SizeSpoofed { declared, actual_so_far } => write!(
                f,
                "size spoofed: declared {} but inflate already produced {} bytes",
                declared, actual_so_far
            ),
            InflateError::SizeMismatch { declared, actual } => {
                write!(f, "size mismatch: declared {} but inflated {}", declared, actual)
            }
            InflateError::Truncated { consumed } => {
                write!(f, "truncated zlib stream after {} input bytes", consumed)
            }
            InflateError::Format(e) => write!(f, "zlib format error: {}", e),
        }
    }
}

/// Inflate a zlib stream starting at `input[0]`, tracking exactly how many
/// input bytes the stream consumes (the zlib boundary). When `declared_size`
/// is given, abort as soon as the output grows past it (size spoofing).
pub fn inflate_stream(input: &[u8], declared_size: Option<u64>) -> Result<InflateResult, InflateError> {
    let mut decomp = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let chunk = 64 * 1024;
    loop {
        let pos = decomp.total_in() as usize;
        if pos >= input.len() {
            return Err(InflateError::Truncated { consumed: pos as u64 });
        }
        let prev_len = out.len();
        out.resize(prev_len + chunk, 0);
        let out_before = decomp.total_out();
        let status = decomp
            .decompress(&input[pos..], &mut out[prev_len..], FlushDecompress::None)
            .map_err(|e| InflateError::Format(e.to_string()))?;
        let produced = (decomp.total_out() - out_before) as usize;
        out.truncate(prev_len + produced);
        if let Some(declared) = declared_size {
            if out.len() as u64 > declared {
                return Err(InflateError::SizeSpoofed {
                    declared,
                    actual_so_far: out.len() as u64,
                });
            }
        }
        match status {
            Status::StreamEnd => {
                let consumed = decomp.total_in();
                if let Some(declared) = declared_size {
                    if out.len() as u64 != declared {
                        return Err(InflateError::SizeMismatch {
                            declared,
                            actual: out.len() as u64,
                        });
                    }
                }
                return Ok(InflateResult { data: out, consumed });
            }
            Status::Ok | Status::BufError => {
                if produced == 0 && decomp.total_in() as usize >= input.len() {
                    return Err(InflateError::Truncated {
                        consumed: decomp.total_in(),
                    });
                }
            }
        }
    }
}

/// Parse a Git loose object file: zlib of "<type> <size>\0<content>".
pub fn parse_loose(data: &[u8]) -> Result<(u8, Vec<u8>), String> {
    let inf = inflate_stream(data, None).map_err(|e| e.to_string())?;
    let raw = inf.data;
    let nul = raw
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| "loose object: missing header NUL".to_string())?;
    let header = std::str::from_utf8(&raw[..nul])
        .map_err(|_| "loose object: bad header".to_string())?;
    let mut parts = header.splitn(2, ' ');
    let tname = parts.next().ok_or("loose object: missing type")?;
    let size: u64 = parts
        .next()
        .ok_or("loose object: missing size")?
        .parse()
        .map_err(|_| "loose object: bad size".to_string())?;
    let tcode = type_code(tname).ok_or_else(|| format!("loose object: unknown type {}", tname))?;
    let content = &raw[nul + 1..];
    if content.len() as u64 != size {
        return Err(format!(
            "loose object: header size {} but content {} bytes",
            size,
            content.len()
        ));
    }
    Ok((tcode, content.to_vec()))
}

