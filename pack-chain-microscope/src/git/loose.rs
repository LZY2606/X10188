use super::checksum::{git_object_id, sha1_hex};
use super::zlib::{inflate_at, ZlibError};

#[derive(Debug, Clone)]
pub struct LooseError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct ParsedLoose {
    pub obj_type: u8,
    pub declared_len: u64,
    pub content: Vec<u8>,
    pub oid_path: String,
    pub oid_computed: String,
    pub oid_matches: bool,
    pub adler_ok: bool,
    pub errors: Vec<LooseError>,
}

fn type_code(name: &[u8]) -> Option<u8> {
    match name {
        b"commit" => Some(1),
        b"tree" => Some(2),
        b"blob" => Some(3),
        b"tag" => Some(4),
        _ => None,
    }
}

pub fn parse_loose(data: &[u8], oid_from_path: &str) -> ParsedLoose {
    let mut errors = Vec::new();
    let mut fail = |code: &str, message: String| ParsedLoose {
        obj_type: 0,
        declared_len: 0,
        content: Vec::new(),
        oid_path: oid_from_path.to_string(),
        oid_computed: String::new(),
        oid_matches: false,
        adler_ok: false,
        errors: vec![LooseError {
            code: code.into(),
            message,
        }],
    };

    let stream = match inflate_at(data, 0) {
        Ok(s) => s,
        Err(ZlibError::Truncated(m)) | Err(ZlibError::BadZlibHeader) => {
            return fail("inflate_failed", m);
        }
    };
    if !stream.adler_ok {
        errors.push(LooseError {
            code: "bad_crc".into(),
            message: format!(
                "zlib adler32 mismatch: trailer {:#010x} computed {:#010x}",
                stream.adler_expected, stream.adler_actual
            ),
        });
    }
    let raw = &stream.data;
    let nul = match raw.iter().position(|&b| b == 0) {
        Some(n) => n,
        None => return fail("bad_header", "no NUL in loose object header".into()),
    };
    let header = &raw[..nul];
    let sp = match header.iter().position(|&b| b == b' ') {
        Some(n) => n,
        None => return fail("bad_header", "no space in loose object header".into()),
    };
    let tname = &header[..sp];
    let len_str = std::str::from_utf8(&header[sp + 1..]).unwrap_or("");
    let declared_len: u64 = len_str.parse().unwrap_or(u64::MAX);
    let obj_type = match type_code(tname) {
        Some(t) => t,
        None => return fail("unknown_type", format!("unknown loose type {:?}", tname)),
    };
    let content = raw[nul + 1..].to_vec();
    if declared_len as usize != content.len() {
        errors.push(LooseError {
            code: "size_spoof".into(),
            message: format!(
                "header claims {} bytes but content is {} bytes",
                declared_len,
                content.len()
            ),
        });
    }
    let oid_computed =
        git_object_id(obj_type, &content).unwrap_or_else(|| sha1_hex(&raw[nul + 1..]));
    let oid_matches = oid_computed == oid_from_path.to_lowercase();
    if !oid_matches {
        errors.push(LooseError {
            code: "oid_mismatch".into(),
            message: format!(
                "recomputed oid {} does not match path oid {}",
                oid_computed, oid_from_path
            ),
        });
    }

    ParsedLoose {
        obj_type,
        declared_len,
        content,
        oid_path: oid_from_path.to_lowercase(),
        oid_computed,
        oid_matches,
        adler_ok: stream.adler_ok,
        errors,
    }
}
