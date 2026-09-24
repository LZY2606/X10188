//! Parse a loose (zlib compressed) Git object.

use crate::git::{git_object_id, inflate_one, GitType};

#[derive(Debug, Clone)]
pub struct LooseParse {
    pub type_name: String,
    pub data: Vec<u8>,
    pub declared_size: usize,
    pub computed_oid: [u8; 20],
    pub error: Option<String>,
}

pub fn parse_loose(data: &[u8]) -> LooseParse {
    let mut error = None;
    let (payload, _used) = match inflate_one(data, 0) {
        Ok(v) => v,
        Err(e) => {
            return LooseParse {
                type_name: String::new(),
                data: Vec::new(),
                declared_size: 0,
                computed_oid: [0u8; 20],
                error: Some(format!("zlib error: {e}")),
            }
        }
    };

    let nul = match payload.iter().position(|b| *b == 0) {
        Some(i) => i,
        None => {
            return LooseParse {
                type_name: String::new(),
                data: Vec::new(),
                declared_size: 0,
                computed_oid: [0u8; 20],
                error: Some("loose object missing NUL header terminator".into()),
            }
        }
    };

    let header = String::from_utf8_lossy(&payload[..nul]).to_string();
    let mut parts = header.split(' ');
    let type_name = parts.next().unwrap_or("").to_string();
    let size_str = parts.next().unwrap_or("");
    let body = payload[nul + 1..].to_vec();

    let declared_size: usize = size_str.parse().unwrap_or(usize::MAX);
    let valid_type = GitType::from_name(&type_name).is_some();
    if !valid_type {
        error = Some(format!("unknown loose object type {type_name:?}"));
    }
    if declared_size != body.len() {
        error = Some(format!(
            "size spoof: loose header declares {declared_size} but body is {} bytes",
            body.len()
        ));
    }
    let computed_oid = git_object_id(&type_name, &body);

    LooseParse {
        type_name,
        data: body,
        declared_size,
        computed_oid,
        error,
    }
}
