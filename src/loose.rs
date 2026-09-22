//! Parser for loose (zlib-compressed, `<type> <size>\0<content>`) objects.

use crate::git::{zlib_decode_at, OBJ_BLOB, OBJ_COMMIT, OBJ_TAG, OBJ_TREE};

pub const MAX_INFLATED_LOOSE: usize = 256 * 1024 * 1024;

pub struct ParsedLoose {
    pub kind: u8,
    pub declared_size: u64,
    pub content: Vec<u8>,
    pub consumed: usize,
    pub errors: Vec<String>,
}

fn parse_header(data: &[u8]) -> Option<(u8, u64, usize)> {
    let nul = data.iter().position(|&b| b == 0)?;
    let header = std::str::from_utf8(&data[..nul]).ok()?;
    let (ty, sz) = header.split_once(' ')?;
    let kind = match ty {
        "commit" => OBJ_COMMIT,
        "tree" => OBJ_TREE,
        "blob" => OBJ_BLOB,
        "tag" => OBJ_TAG,
        other => {
            let _ = other;
            return None;
        }
    };
    let size: u64 = sz.parse().ok()?;
    Some((kind, size, nul + 1))
}

pub fn parse_loose(data: &[u8]) -> ParsedLoose {
    let mut out = ParsedLoose {
        kind: 0,
        declared_size: 0,
        content: Vec::new(),
        consumed: 0,
        errors: Vec::new(),
    };
    let z = match zlib_decode_at(data, 0, MAX_INFLATED_LOOSE) {
        Ok(z) => z,
        Err(e) => {
            out.errors
                .push(format!("zlib decompression failed: {e}"));
            return out;
        }
    };
    out.consumed = z.consumed;
    let Some((kind, size, hlen)) = parse_header(&z.data) else {
        out.errors
            .push("invalid loose object header (expected `<type> <size>\\0`)".into());
        return out;
    };
    out.kind = kind;
    out.declared_size = size;
    let body = &z.data[hlen..];
    out.content = body.to_vec();
    if body.len() as u64 != size {
        out.errors.push(format!(
            "size spoof: header declares {size} bytes but payload is {} bytes",
            body.len()
        ));
    }
    out
}
