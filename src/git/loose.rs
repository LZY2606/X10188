//! Loose object parsing: a single zlib stream of `"<type> <len>\0<content>"`.

use crate::git::object::{git_object_id, ObjType};
use crate::git::zlib::InflateError;

#[derive(Debug, Clone)]
pub struct LooseObject {
    pub kind: ObjType,
    pub content: Vec<u8>,
    pub computed_oid: [u8; 20],
}

#[derive(Debug, PartialEq, Eq)]
pub enum LooseError {
    Inflate(String),
    MalformedHeader(String),
    BadSize,
}

impl std::fmt::Display for LooseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LooseError::Inflate(s) => write!(f, "loose inflate failed: {s}"),
            LooseError::MalformedHeader(s) => write!(f, "loose header malformed: {s}"),
            LooseError::BadSize => f.write_str("loose header size does not match content"),
        }
    }
}

pub fn parse_loose(data: &[u8]) -> Result<LooseObject, LooseError> {
    // Loose objects do not carry a declared size outside the stream; inflate with a high bound
    // and rely on the embedded header for verification.
    let inf = inflate_stream_unknown(data).map_err(|e| LooseError::Inflate(e.to_string()))?;
    let nul = inf
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| LooseError::MalformedHeader("missing NUL".into()))?;
    let header = std::str::from_utf8(&inf[..nul])
        .map_err(|_| LooseError::MalformedHeader("non-utf8 header".into()))?;
    let (name, len_str) = header
        .split_once(' ')
        .ok_or_else(|| LooseError::MalformedHeader("expected 'type length'".into()))?;
    let kind = ObjType::from_name(name)
        .ok_or_else(|| LooseError::MalformedHeader(format!("unknown type {name}")))?;
    let declared_len: usize = len_str
        .parse()
        .map_err(|_| LooseError::MalformedHeader("bad length".into()))?;
    let content = &inf[nul + 1..];
    if content.len() != declared_len {
        return Err(LooseError::BadSize);
    }
    let content = content.to_vec();
    let computed_oid = git_object_id(kind, &content);
    Ok(LooseObject {
        kind,
        content,
        computed_oid,
    })
}

fn inflate_stream_unknown(data: &[u8]) -> Result<Vec<u8>, InflateError> {
    use flate2::{Decompress, FlushDecompress};
    let mut out = Vec::new();
    let mut dec = Decompress::new(false);
    let mut pos = 0usize;
    loop {
        let before_in = dec.total_in();
        let before_out = dec.total_out();
        let mut chunk = [0u8; 16 * 1024];
        let status = dec
            .decompress(&data[pos..], &mut chunk, FlushDecompress::None)
            .map_err(|e| InflateError::Corrupt(e.to_string()))?;
        pos += (dec.total_in() - before_in) as usize;
        let wrote = (dec.total_out() - before_out) as usize;
        out.extend_from_slice(&chunk[..wrote]);
        if status == flate2::Status::StreamEnd {
            break;
        }
        if (dec.total_in() - before_in) == 0 && wrote == 0 {
            return Err(InflateError::Truncated {
                expected: 0,
                produced: out.len() as u64,
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git::builder::write_loose_object;

    #[test]
    fn loose_roundtrip() {
        let raw = write_loose_object(ObjType::Blob, b"loose body");
        let parsed = parse_loose(&raw).unwrap();
        assert_eq!(parsed.content, b"loose body");
        assert_eq!(parsed.kind, ObjType::Blob);
        assert_eq!(
            hex::encode(parsed.computed_oid),
            hex::encode(git_object_id(ObjType::Blob, b"loose body"))
        );
    }
}
