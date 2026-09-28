//! Loose object parsing: a single zlib stream of `"<type> <size>\0<body>"`.

use crate::error::{Error, Result};
use crate::git::{parse_object_header, LeafType};
use crate::models::Issue;
use crate::pack::PARSE_HARD_CAP;
use crate::zlib;

#[derive(Debug)]
pub struct ParsedLoose {
    pub leaf: LeafType,
    pub declared_size: u64,
    pub body: Vec<u8>,
    pub header_len: usize,
    pub stream_finished: bool,
    pub compressed_len: usize,
    pub over_cap: bool,
    pub issues: Vec<Issue>,
}

pub fn parse_loose(buf: &[u8]) -> Result<ParsedLoose> {
    let mut issues = Vec::new();
    let inf = zlib::inflate_all(buf, PARSE_HARD_CAP)
        .map_err(|e| Error::Zlib(format!("loose object: {e}")))?;
    let (leaf, declared_size, header_len) = parse_object_header(&inf.data)
        .ok_or_else(|| Error::Format("loose object missing valid `<type> <size>\\0` header".into()))?;

    if inf.over_cap {
        issues.push(Issue::error("size_bomb", format!("loose object exceeds hard cap {PARSE_HARD_CAP}")));
    }
    let body_len = inf.data.len().saturating_sub(header_len) as u64;
    if body_len != declared_size {
        issues.push(Issue::error(
            "size_lie",
            format!("loose header declares {declared_size} bytes but body is {body_len} bytes"),
        ));
    }
    let body = inf.data[header_len.min(inf.data.len())..].to_vec();

    Ok(ParsedLoose {
        leaf,
        declared_size,
        body,
        header_len,
        stream_finished: inf.finished,
        compressed_len: inf.consumed,
        over_cap: inf.over_cap,
        issues,
    })
}
