//! Git object primitives: type names, object id computation, bounded zlib.

use flate2::{Decompress, FlushDecompress, Status};
use sha1::{Digest, Sha1};

pub const OBJ_COMMIT: u8 = 1;
pub const OBJ_TREE: u8 = 2;
pub const OBJ_BLOB: u8 = 3;
pub const OBJ_TAG: u8 = 4;
pub const OBJ_OFS_DELTA: u8 = 6;
pub const OBJ_REF_DELTA: u8 = 7;

pub fn type_name(t: u8) -> &'static str {
    match t {
        OBJ_COMMIT => "commit",
        OBJ_TREE => "tree",
        OBJ_BLOB => "blob",
        OBJ_TAG => "tag",
        OBJ_OFS_DELTA => "ofs-delta",
        OBJ_REF_DELTA => "ref-delta",
        _ => "unknown",
    }
}

pub fn type_id(name: &str) -> Option<u8> {
    match name {
        "commit" => Some(OBJ_COMMIT),
        "tree" => Some(OBJ_TREE),
        "blob" => Some(OBJ_BLOB),
        "tag" => Some(OBJ_TAG),
        _ => None,
    }
}

pub fn is_delta(t: u8) -> bool {
    t == OBJ_OFS_DELTA || t == OBJ_REF_DELTA
}

/// Compute the Git object id (hex) for a fully reconstructed object.
pub fn compute_oid(type_name: &str, content: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(format!("{} {}\0", type_name, content.len()).as_bytes());
    h.update(content);
    hex::encode(h.finalize())
}

/// Inflate a zlib stream starting at `input[0]`.
///
/// Returns `(bytes, consumed)` where `consumed` is the exact number of input
/// bytes belonging to the zlib stream (the zlib boundary). The output is
/// capped at `max_out` bytes; exceeding the cap yields `Err("output-limit")`
/// so callers can distinguish size deception from truncation.
pub fn inflate_bounded(input: &[u8], max_out: usize) -> Result<(Vec<u8>, usize), String> {
    let mut d = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    let mut rest = input;
    loop {
        let before_in = d.total_in();
        let before_out = d.total_out();
        let status = d
            .decompress(rest, &mut chunk, FlushDecompress::None)
            .map_err(|e| format!("zlib error: {e}"))?;
        let produced = (d.total_out() - before_out) as usize;
        let consumed_now = (d.total_in() - before_in) as usize;
        if out.len() + produced > max_out {
            return Err("output-limit".into());
        }
        out.extend_from_slice(&chunk[..produced]);
        rest = &rest[consumed_now..];
        match status {
            Status::StreamEnd => return Ok((out, d.total_in() as usize)),
            Status::Ok | Status::BufError => {
                if consumed_now == 0 && produced == 0 {
                    return Err("zlib stream truncated before end-of-stream".into());
                }
            }
        }
    }
}

/// Parse a loose object file (zlib of "type size\0content").
/// Returns (type_name, content, declared_size).
pub fn parse_loose(raw: &[u8]) -> Result<(String, Vec<u8>, u64), String> {
    let (data, _consumed) = inflate_bounded(raw, 512 * 1024 * 1024)?;
    let nul = data
        .iter()
        .position(|&b| b == 0)
        .ok_or("loose object header missing NUL")?;
    let header = std::str::from_utf8(&data[..nul]).map_err(|_| "bad loose header utf8")?;
    let mut it = header.splitn(2, ' ');
    let tname = it.next().ok_or("loose header missing type")?;
    if type_id(tname).is_none() {
        return Err(format!("unknown loose object type '{tname}'"));
    }
    let size: u64 = it
        .next()
        .ok_or("loose header missing size")?
        .parse()
        .map_err(|_| "loose header bad size")?;
    let content = data[nul + 1..].to_vec();
    if content.len() as u64 != size {
        return Err(format!(
            "loose object size deception: header says {size}, actual {}",
            content.len()
        ));
    }
    Ok((tname.to_string(), content, size))
}

/// Git-style varint used inside delta streams (little-endian 7-bit groups).
pub fn read_delta_varint(data: &[u8], pos: &mut usize) -> Result<u64, String> {
    let mut shift = 0u32;
    let mut val: u64 = 0;
    loop {
        if *pos >= data.len() {
            return Err("delta varint truncated".into());
        }
        let b = data[*pos];
        *pos += 1;
        val |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return Ok(val);
        }
        if shift > 63 {
            return Err("delta varint overflow".into());
        }
    }
}
