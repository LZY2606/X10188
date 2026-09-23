//! Loose object parsing: one zlib stream containing the raw object
//! framing. The object id is normally implied by the `xx/<38hex>`
//! storage path and is checked against the recomputed SHA-1.

use crate::model::error_code;
use crate::model::Oid;
use crate::parse::git_object::{parse_loose_body, RawObject};
use crate::parse::zlib;

#[derive(Debug, Clone)]
pub struct LooseIssue {
    pub code: &'static str,
    pub message: String,
    pub evidence_hex: String,
}

#[derive(Debug, Clone)]
pub struct ParsedLoose {
    /// Oid implied by the path, if any.
    pub path_oid: Option<Oid>,
    pub object: Option<RawObject>,
    pub computed_oid: Option<String>,
    /// Bytes consumed from the zlib stream (should cover the whole file).
    pub consumed: Option<usize>,
    pub total_len: usize,
    pub issues: Vec<LooseIssue>,
}

/// Try to extract an oid from a path component `xx/yyyy...` (38 hex tail).
pub fn oid_from_path(rel_path: &str) -> Option<Oid> {
    let norm = rel_path.replace('\\', "/");
    let parts: Vec<&str> = norm.split('/').collect();
    if parts.len() < 2 {
        return None;
    }
    let dir = parts[parts.len() - 2];
    let file = parts[parts.len() - 1];
    if dir.len() == 2
        && file.len() == 38
        && dir.bytes().all(|b| b.is_ascii_hexdigit())
        && file.bytes().all(|b| b.is_ascii_hexdigit())
    {
        Some(Oid(format!("{dir}{file}")))
    } else {
        None
    }
}

pub fn parse_loose(data: &[u8], rel_path: &str, object_cap: u64) -> ParsedLoose {
    let path_oid = oid_from_path(rel_path);
    let mut issues = Vec::new();

    let inflated = match zlib::inflate(data, object_cap) {
        Ok(g) => g,
        Err(e) => {
            issues.push(LooseIssue {
                code: e.code,
                message: format!("{} (partial {} bytes)", e.message, e.partial_len),
                evidence_hex: hex::encode(&data[..data.len().min(16)]),
            });
            return ParsedLoose {
                path_oid,
                object: None,
                computed_oid: None,
                consumed: None,
                total_len: data.len(),
                issues,
            };
        }
    };

    if inflated.consumed != data.len() {
        issues.push(LooseIssue {
            code: error_code::ZLIB_TRAILING,
            message: format!("{} trailing bytes after zlib stream", data.len() - inflated.consumed),
            evidence_hex: hex::encode(&data[inflated.consumed..(inflated.consumed + 8).min(data.len())]),
        });
    }

    let object = match parse_loose_body(&inflated.data) {
        Ok(obj) => obj,
        Err(message) => {
            issues.push(LooseIssue {
                code: error_code::LOOSE_HEADER,
                message,
                evidence_hex: hex::encode(&inflated.data[..inflated.data.len().min(24)]),
            });
            return ParsedLoose {
                path_oid,
                object: None,
                computed_oid: None,
                consumed: Some(inflated.consumed),
                total_len: data.len(),
                issues,
            };
        }
    };

    let computed = object.oid();
    if let Some(expected) = &path_oid {
        if expected.0 != computed {
            issues.push(LooseIssue {
                code: error_code::HASH_MISMATCH,
                message: format!(
                    "path oid {} != recomputed {}",
                    expected.short(),
                    &computed[..10]
                ),
                evidence_hex: String::new(),
            });
        }
    }

    ParsedLoose {
        path_oid,
        object: Some(object),
        computed_oid: Some(computed),
        consumed: Some(inflated.consumed),
        total_len: data.len(),
        issues,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_extraction() {
        let oid = oid_from_path("objects/a1/b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5").unwrap();
        assert!(oid.0.starts_with("a1b2c3d4e5"));
        assert!(oid_from_path("random/file.bin").is_none());
    }
}
