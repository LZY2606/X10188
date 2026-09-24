//! Parser for loose objects: a single zlib stream of `<type> <size>\0<content>`.

use crate::binformat::{git_object_id, inflate_zlib};
use crate::models::Evidence;

#[derive(Debug, Clone)]
pub struct ParsedLoose {
    pub type_name: String,
    pub content: Vec<u8>,
    pub declared_size: u64,
    pub actual_size: u64,
    pub size_ok: bool,
    pub computed_oid: [u8; 20],
    pub overran_cap: bool,
    pub evidence: Vec<Evidence>,
    pub parse_error: Option<String>,
}

/// Parse a loose object file. `expected_oid` (the oid derived from the
/// `xx/xxx...` import path) is checked against the recomputed id.
pub fn parse_loose(data: &[u8], expected_oid: Option<[u8; 20]>, hard_cap: usize) -> ParsedLoose {
    let mut evidence = Vec::new();
    let inf = match inflate_zlib(data, 0, u64::MAX, hard_cap) {
        Ok(inf) => inf,
        Err(e) => {
            return ParsedLoose {
                type_name: String::new(),
                content: Vec::new(),
                declared_size: 0,
                actual_size: 0,
                size_ok: false,
                computed_oid: [0u8; 20],
                overran_cap: false,
                evidence: vec![Evidence::new("zlib_error", e.clone())],
                parse_error: Some(e),
            };
        }
    };

    let nul = match inf.data.iter().position(|&b| b == 0) {
        Some(n) => n,
        None => {
            evidence.push(Evidence::new("loose_header", "missing NUL terminator in loose header"));
            return ParsedLoose {
                type_name: String::new(),
                content: Vec::new(),
                declared_size: 0,
                actual_size: inf.data.len() as u64,
                size_ok: false,
                computed_oid: [0u8; 20],
                overran_cap: inf.overran_cap,
                evidence,
                parse_error: Some("bad loose header".into()),
            };
        }
    };
    let header = String::from_utf8_lossy(&inf.data[..nul]);
    let mut parts = header.splitn(2, ' ');
    let type_name = parts.next().unwrap_or("").to_string();
    let declared_size: u64 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(u64::MAX);
    let content = inf.data[nul + 1..].to_vec();
    let actual_size = content.len() as u64;
    let size_ok = declared_size == actual_size;
    if !size_ok {
        evidence.push(Evidence::new(
            "size_spoof",
            format!("loose header declares {} bytes but body is {} bytes", declared_size, actual_size),
        ));
    }
    if inf.overran_cap {
        evidence.push(Evidence::new(
            "size_spoof_overrun",
            format!("loose object exceeds hard cap {} bytes", hard_cap),
        ));
    }

    let computed_oid = git_object_id(&type_name, &content);
    if let Some(expected) = expected_oid {
        if expected != computed_oid {
            evidence.push(Evidence::new(
                "oid_mismatch",
                format!(
                    "loose path oid {} but recomputed object id is {}",
                    hex::encode(expected),
                    hex::encode(computed_oid)
                ),
            ));
        }
    }

    ParsedLoose {
        type_name,
        content,
        declared_size,
        actual_size,
        size_ok,
        computed_oid,
        overran_cap: inf.overran_cap,
        evidence,
        parse_error: None,
    }
}
