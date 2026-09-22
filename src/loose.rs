use std::path::Path;

use crate::delta::{object_frame, ObjectType};
use crate::error::{Error, Result};
use crate::hash::sha1_hex;
use crate::inflate::inflate_limited;

#[derive(Debug, Clone)]
pub struct ParsedLoose {
    pub object_type: ObjectType,
    pub declared_body_size: u64,
    pub actual_body_size: u64,
    pub actual_oid: String,
    pub body: Vec<u8>,
}

pub fn parse_loose_path(path: &Path) -> Result<ParsedLoose> {
    parse_loose(&std::fs::read(path)?)
}

pub fn parse_loose(data: &[u8]) -> Result<ParsedLoose> {
    let mut inflater = flate2::Decompress::new(true);
    let mut out = Vec::new();
    let status = inflater
        .decompress_vec(data, &mut out, &mut [0u8; 0], flate2::FlushDecompress::Finish)
        .map_err(|e| Error::Corrupt(format!("loose zlib error: {e}")))?;
    if status != flate2::Status::StreamEnd {
        return Err(Error::Corrupt("loose object did not reach zlib end".into()));
    }
    let null = out
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| Error::Corrupt("loose object header missing NUL".into()))?;
    let header = std::str::from_utf8(&out[..null])
        .map_err(|_| Error::Corrupt("loose header is not UTF-8".into()))?;
    let (name, size_text) = header
        .split_once(' ')
        .ok_or_else(|| Error::Corrupt("loose header missing size".into()))?;
    let object_type = ObjectType::named(name)
        .ok_or_else(|| Error::Corrupt(format!("unsupported loose object type {name}")))?;
    let declared_body_size: u64 = size_text
        .parse()
        .map_err(|_| Error::Corrupt("loose header size is not numeric".into()))?;
    let body = out[null + 1..].to_vec();
    if body.len() as u64 != declared_body_size {
        return Err(Error::Corrupt(format!(
            "loose declared size {declared_body_size}, actual {}",
            body.len()
        )));
    }
    let frame = object_frame(name, &body);
    let actual_oid = sha1_hex(&frame);
    Ok(ParsedLoose {
        object_type,
        declared_body_size,
        actual_body_size: body.len() as u64,
        actual_oid,
        body,
    })
}
