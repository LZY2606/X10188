//! Loose object handling: zlib-compressed `<type> <len>\0<content>`.

use crate::gitobj::{object_id, split_frame};
use crate::zstream::inflate_from;

#[derive(Debug, Clone)]
pub struct ParsedLoose {
    pub obj_type: u8,
    pub content: Vec<u8>,
    pub computed_oid: [u8; 20],
    /// Set when the file's name looks like a git oid.
    pub claimed_oid: Option<[u8; 20]>,
    pub oid_matches: bool,
    pub error: Option<String>,
}

pub fn parse_loose(
    data: &[u8],
    claimed_oid: Option<[u8; 20]>,
    max_bytes: u64,
) -> ParsedLoose {
    let outcome = inflate_from(data, 0, None, max_bytes);
    match outcome {
        Ok(oc) => match split_frame(&oc.data) {
            Some((t, body)) => {
                let oid = object_id(t, body);
                let matches_claim = claimed_oid.map(|c| c == oid).unwrap_or(true);
                ParsedLoose {
                    obj_type: t,
                    content: body.to_vec(),
                    computed_oid: oid,
                    claimed_oid,
                    oid_matches: matches_claim,
                    error: None,
                }
            }
            None => ParsedLoose {
                obj_type: 0,
                content: Vec::new(),
                computed_oid: [0u8; 20],
                claimed_oid,
                oid_matches: false,
                error: Some("loose frame malformed: '<type> <len>\\0' header invalid".into()),
            },
        },
        Err(e) => ParsedLoose {
            obj_type: 0,
            content: e.partial,
            computed_oid: [0u8; 20],
            claimed_oid,
            oid_matches: false,
            error: Some(e.message),
        },
    }
}
