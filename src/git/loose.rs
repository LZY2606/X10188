use crate::git::object::{parse_object_frame, ObjType};
use crate::git::sha::object_id;
use crate::git::zlib::inflate_zlib;
use serde::Serialize;

pub const MAX_LOOSE_INFLATED: usize = 512 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct LooseSummary {
    /// Oid claimed by the path (`ab/cdef...`), if the import path encoded one.
    pub claimed_oid: Option<String>,
    pub kind: Option<ObjType>,
    pub declared_size: Option<usize>,
    pub actual_size: Option<usize>,
    pub computed_oid: Option<String>,
    pub body: Option<Vec<u8>>,
    pub zlib_input_consumed: usize,
    pub error: Option<String>,
}

pub fn parse_loose(data: &[u8], claimed_oid: Option<String>) -> LooseSummary {
    let mut s = LooseSummary {
        claimed_oid,
        kind: None,
        declared_size: None,
        actual_size: None,
        computed_oid: None,
        body: None,
        zlib_input_consumed: 0,
        error: None,
    };
    let inflated = match inflate_zlib(data, MAX_LOOSE_INFLATED) {
        Ok(v) => v,
        Err(e) => {
            s.error = Some(format!("zlib error: {:?}", e));
            return s;
        }
    };
    s.zlib_input_consumed = inflated.input_consumed;
    match parse_object_frame(&inflated.data) {
        Ok((kind, body)) => {
            let computed = object_id(kind.name(), &body);
            s.declared_size = Some(body.len());
            s.actual_size = Some(inflated.data.len());
            s.kind = Some(kind);
            s.body = Some(body);
            s.computed_oid = Some(computed.clone());
            if let Some(want) = &s.claimed_oid {
                if !want.eq_ignore_ascii_case(&computed) {
                    s.error = Some(format!(
                        "loose object oid mismatch: path {} content {}",
                        want, computed
                    ));
                }
            }
        }
        Err(e) => s.error = Some(e),
    }
    s
}

/// Encode a git object into the loose zlib frame for tests / exports.
pub fn encode_loose(kind: ObjType, body: &[u8]) -> Vec<u8> {
    let frame = format!("{} {}\0", kind.name(), body.len());
    let mut full = frame.into_bytes();
    full.extend_from_slice(body);
    crate::git::zlib::deflate_zlib(&full)
}
