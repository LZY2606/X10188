use crate::git::{bounded_decompress_local, ObjectId, ObjectType};

#[derive(Debug, Clone)]
pub struct LooseParse {
    pub kind: ObjectType,
    pub declared_size: u64,
    pub data: Vec<u8>,
    pub payload_offset: usize,
    pub actual_oid: ObjectId,
}

pub fn parse_loose(data: &[u8]) -> Result<LooseParse, String> {
    let result = bounded_decompress_local(data, u64::MAX / 4)?;
    let nul = result.data.iter().position(|b| *b == 0).ok_or("loose object header missing NUL")?;
    let header = std::str::from_utf8(&result.data[..nul]).map_err(|_| "non-UTF8 loose header")?;
    let (name, size_text) = header.split_once(' ').ok_or("malformed loose header")?;
    let kind = match name {
        "commit" => ObjectType::Commit,
        "tree" => ObjectType::Tree,
        "blob" => ObjectType::Blob,
        "tag" => ObjectType::Tag,
        other => return Err(format!("unsupported loose type {other}")),
    };
    let declared_size = size_text.parse::<u64>().map_err(|_| "bad loose size")?;
    let object = result.data[nul+1..].to_vec();
    if object.len() as u64 != declared_size {
        return Err(format!("loose size spoof: header {declared_size}, actual {}", object.len()));
    }
    let actual_oid = crate::git::object_id(kind, &object);
    Ok(LooseParse { kind, declared_size, data: object, payload_offset: 0, actual_oid })
}
