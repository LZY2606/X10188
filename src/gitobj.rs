use sha1::{Digest, Sha1};

pub const T_COMMIT: u8 = 1;
pub const T_TREE: u8 = 2;
pub const T_BLOB: u8 = 3;
pub const T_TAG: u8 = 4;
pub const T_OFS_DELTA: u8 = 6;
pub const T_REF_DELTA: u8 = 7;

pub fn type_name(code: u8) -> &'static str {
    match code {
        T_COMMIT => "commit",
        T_TREE => "tree",
        T_BLOB => "blob",
        T_TAG => "tag",
        T_OFS_DELTA => "ofs_delta",
        T_REF_DELTA => "ref_delta",
        _ => "unknown",
    }
}

pub fn is_base_type(name: &str) -> bool {
    matches!(name, "commit" | "tree" | "blob" | "tag")
}

/// Git object id: sha1("<type> <len>\0" + content)
pub fn compute_oid(obj_type: &str, content: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(format!("{} {}\0", obj_type, content.len()).as_bytes());
    h.update(content);
    hex::encode(h.finalize())
}

/// Parse a loose object file (zlib of "type size\0content").
pub fn parse_loose(data: &[u8]) -> Result<(String, Vec<u8>), String> {
    let (raw, _consumed) = crate::zlib::inflate_all(data, 512 << 20)?;
    let nul = raw
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| "loose 头缺少 NUL 分隔".to_string())?;
    let header = std::str::from_utf8(&raw[..nul]).map_err(|_| "loose 头非 UTF-8".to_string())?;
    let mut it = header.splitn(2, ' ');
    let tname = it.next().ok_or_else(|| "loose 头缺类型".to_string())?;
    if !is_base_type(tname) {
        return Err(format!("loose 类型未知: {}", tname));
    }
    let size: u64 = it
        .next()
        .and_then(|s| s.trim().parse().ok())
        .ok_or_else(|| "loose 头缺大小".to_string())?;
    let content = raw[nul + 1..].to_vec();
    if content.len() as u64 != size {
        return Err(format!(
            "loose 大小欺骗: 声明 {} 实际 {}",
            size,
            content.len()
        ));
    }
    Ok((tname.to_string(), content))
}
