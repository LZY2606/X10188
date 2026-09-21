//! Loose object parsing: `<type> <size>\0<payload>` framing stored zlib
//! compressed under `objects/xx/yyyy...`.

use crate::git::{git_object_id, ObjType};

#[derive(Debug, Clone)]
pub struct RawLoose {
    pub obj_type: ObjType,
    pub declared_size: usize,
    pub payload: Vec<u8>,
    pub computed_oid: String,
    pub size_spoof: bool,
}

pub fn parse_loose(data: &[u8], inflate_limit: usize) -> Result<RawLoose, String> {
    let z = crate::zlibm::inflate_member(data, 0, inflate_limit)?;
    let nul = z
        .data
        .iter()
        .position(|b| *b == 0)
        .ok_or("loose object missing NUL header terminator")?;
    let header = std::str::from_utf8(&z.data[..nul]).map_err(|e| e.to_string())?;
    let (type_name, size_text) = header
        .split_once(' ')
        .ok_or("loose header missing size")?;
    let obj_type = ObjType::parse_loose(type_name).ok_or_else(|| {
        format!("loose object has unknown type {type_name:?}")
    })?;
    let declared: usize = size_text
        .parse()
        .map_err(|_| format!("loose header bad size {size_text:?}"))?;
    let payload = z.data[nul + 1..].to_vec();
    let size_spoof = payload.len() != declared;
    let computed_oid = git_object_id(obj_type, &payload);
    Ok(RawLoose {
        obj_type,
        declared_size: declared,
        payload,
        computed_oid,
        size_spoof,
    })
}
