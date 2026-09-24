use crate::model::ObjType;
use crate::zlibx;

pub struct LooseObject {
    pub obj_type: ObjType,
    pub declared_size: u64,
    pub content: Vec<u8>,
    pub compressed_len: usize,
}

pub fn parse_loose(bytes: &[u8]) -> Result<LooseObject, String> {
    let (raw, consumed) = zlibx::decompress_with_boundary(bytes, crate::pack::IMPORT_DECOMPRESS_CAP)?;
    let nul = raw
        .iter()
        .position(|b| *b == 0)
        .ok_or("loose 对象缺少 header 终止符")?;
    let header = std::str::from_utf8(&raw[..nul]).map_err(|_| "loose header 非 UTF-8".to_string())?;
    let (typ, size) = header
        .split_once(' ')
        .ok_or_else(|| format!("loose header 格式错误: {header:?}"))?;
    let obj_type = match typ {
        "commit" => ObjType::Commit,
        "tree" => ObjType::Tree,
        "blob" => ObjType::Blob,
        "tag" => ObjType::Tag,
        other => return Err(format!("loose 对象类型未知: {other}")),
    };
    let declared_size: u64 = size
        .parse()
        .map_err(|_| format!("loose header 大小无法解析: {size:?}"))?;
    let content = raw[nul + 1..].to_vec();
    Ok(LooseObject {
        obj_type,
        declared_size,
        content,
        compressed_len: consumed,
    })
}

pub fn encode_loose(obj_type: ObjType, content: &[u8]) -> Vec<u8> {
    let header = format!("{} {}\0", obj_type.git_name().unwrap(), content.len());
    let mut raw = header.into_bytes();
    raw.extend_from_slice(content);
    zlibx::compress(&raw)
}
