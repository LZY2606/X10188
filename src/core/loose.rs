// Loose object parsing (a single zlib stream of "<type> <size>\0<content>").

use super::git::parse_loose_header;

#[derive(Clone, Debug)]
pub struct ParsedLoose {
    /// Object id advertised by the on-disk path (xx/yyyy...), if available.
    pub path_oid: Option<[u8; 20]>,
    pub kind: super::git::GitType,
    pub content: Result<Vec<u8>, String>,
    pub declared_size: u64,
    /// Consumed compressed bytes from the start of the file.
    pub consumed: Option<usize>,
}

/// Inflate up to a loose object. We inflate generously first (up to a cap is
/// not needed here because the stream is self-delimiting via StreamEnd), but
/// still detect streams that fail to terminate.
pub fn parse_loose(buf: &[u8], path_oid: Option<[u8; 20]>) -> ParsedLoose {
    let mut d = flate2::Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut pos = 0usize;
    let inflate_result = loop {
        let mut tmp = [0u8; 8192];
        let in_before = d.total_in();
        let out_before = d.total_out();
        match d.inflate(&buf[pos..], &mut tmp, flate2::FlushDecompress::None) {
            Ok(status) => {
                pos += (d.total_in() - in_before) as usize;
                let produced = (d.total_out() - out_before) as usize;
                out.extend_from_slice(&tmp[..produced]);
                if status == flate2::Status::StreamEnd {
                    break Ok(pos);
                }
                if status == flate2::Status::BufError && produced == 0 && pos == buf.len() {
                    break Err::<usize, String>("loose zlib stream truncated".into());
                }
            }
            Err(e) => break Err(e.to_string()),
        }
    };

    match inflate_result {
        Err(e) => ParsedLoose {
            path_oid,
            kind: super::git::GitType::Blob,
            content: Err(e),
            declared_size: 0,
            consumed: None,
        },
        Ok(consumed) => {
            match parse_loose_header(&out) {
                Err(e) => ParsedLoose {
                    path_oid,
                    kind: super::git::GitType::Blob,
                    content: Err(format!("loose header: {e}")),
                    declared_size: 0,
                    consumed: Some(consumed),
                },
                Ok((kind, size, body_start)) => {
                    let body = out[body_start..].to_vec();
                    let content = if body.len() == size {
                        Ok(body)
                    } else {
                        Err(format!(
                            "loose header declares {size} bytes but body is {} bytes",
                            body.len()
                        ))
                    };
                    ParsedLoose {
                        path_oid,
                        kind,
                        content,
                        declared_size: size as u64,
                        consumed: Some(consumed),
                    }
                }
            }
        }
    }
}

/// Try to interpret an import path like "ab/cdef...<38 hex>" as an object id.
pub fn oid_from_relpath(relpath: &str) -> Option<[u8; 20]> {
    let cleaned = relpath.replace('/', "").replace('\\', "");
    if cleaned.len() != 40 || !cleaned.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut oid = [0u8; 20];
    hex::decode_to_slice(cleaned.as_bytes(), &mut oid).ok()?;
    Some(oid)
}
