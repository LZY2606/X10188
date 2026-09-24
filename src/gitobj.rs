//! Git 对象基础：object id 计算、varint、受限 zlib 解压、loose object 解析。
//! 核心解析不调用系统 git。

use flate2::{Decompress, FlushDecompress, Status};
use sha1::{Digest, Sha1};

pub const OID_LEN: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjType {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
}

impl ObjType {
    pub fn from_pack_code(code: u8) -> Option<ObjType> {
        match code {
            1 => Some(ObjType::Commit),
            2 => Some(ObjType::Tree),
            3 => Some(ObjType::Blob),
            4 => Some(ObjType::Tag),
            6 => Some(ObjType::OfsDelta),
            7 => Some(ObjType::RefDelta),
            _ => None,
        }
    }
    pub fn pack_code(self) -> u8 {
        match self {
            ObjType::Commit => 1,
            ObjType::Tree => 2,
            ObjType::Blob => 3,
            ObjType::Tag => 4,
            ObjType::OfsDelta => 6,
            ObjType::RefDelta => 7,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            ObjType::Commit => "commit",
            ObjType::Tree => "tree",
            ObjType::Blob => "blob",
            ObjType::Tag => "tag",
            ObjType::OfsDelta => "ofs_delta",
            ObjType::RefDelta => "ref_delta",
        }
    }
    pub fn is_delta(self) -> bool {
        matches!(self, ObjType::OfsDelta | ObjType::RefDelta)
    }
    pub fn from_name(name: &str) -> Option<ObjType> {
        match name {
            "commit" => Some(ObjType::Commit),
            "tree" => Some(ObjType::Tree),
            "blob" => Some(ObjType::Blob),
            "tag" => Some(ObjType::Tag),
            _ => None,
        }
    }
}

/// 计算 Git object id: sha1("<type> <len>\\0" + content)
pub fn object_id(obj_type: ObjType, content: &[u8]) -> [u8; OID_LEN] {
    let mut h = Sha1::new();
    h.update(format!("{} {}\0", obj_type.name(), content.len()).as_bytes());
    h.update(content);
    let out = h.finalize();
    let mut oid = [0u8; OID_LEN];
    oid.copy_from_slice(&out);
    oid
}

pub fn oid_hex(oid: &[u8]) -> String {
    hex::encode(oid)
}

#[derive(Debug)]
pub enum InflateError {
    Zlib(String),
    Truncated,
    /// 解压输出超过上限（用于发现大小欺骗 / 预算控制）
    SizeExceeded { limit: u64 },
}

impl std::fmt::Display for InflateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InflateError::Zlib(e) => write!(f, "zlib 错误: {e}"),
            InflateError::Truncated => write!(f, "zlib 流被截断"),
            InflateError::SizeExceeded { limit } => {
                write!(f, "解压输出超过上限 {limit} 字节（疑似大小欺骗）")
            }
        }
    }
}

/// 受限解压：输出超过 max_out 立即报错。
/// 返回 (解压结果, 消耗的输入字节数) —— 消耗的输入字节数即 zlib 流边界。
pub fn inflate_bounded(input: &[u8], max_out: u64) -> Result<(Vec<u8>, usize), InflateError> {
    let mut d = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        let in_before = d.total_in() as usize;
        let out_before = d.total_out() as usize;
        if in_before >= input.len() {
            return Err(InflateError::Truncated);
        }
        let status = d
            .decompress(&input[in_before..], &mut chunk, FlushDecompress::None)
            .map_err(|e| InflateError::Zlib(e.to_string()))?;
        let produced = d.total_out() as usize - out_before;
        out.extend_from_slice(&chunk[..produced]);
        if out.len() as u64 > max_out {
            return Err(InflateError::SizeExceeded { limit: max_out });
        }
        match status {
            Status::StreamEnd => return Ok((out, d.total_in() as usize)),
            Status::Ok | Status::BufError => {
                if produced == 0 && d.total_in() as usize == in_before {
                    return Err(InflateError::Truncated);
                }
            }
        }
    }
}

/// 解析 Git 风格的 size varint（delta 头、loose 不使用，pack 对象头用 pack_varint）
pub fn parse_size_varint(data: &[u8], pos: &mut usize) -> Option<u64> {
    let mut shift = 0u32;
    let mut val: u64 = 0;
    loop {
        if *pos >= data.len() || shift > 63 {
            return None;
        }
        let b = data[*pos];
        *pos += 1;
        val |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return Some(val);
        }
    }
}

pub struct LooseObject {
    pub obj_type: ObjType,
    pub declared_size: u64,
    pub content: Vec<u8>,
    pub oid: [u8; OID_LEN],
    pub compressed_len: usize,
}

/// 解析 loose object（zlib("<type> <size>\\0" + content)）
pub fn parse_loose(data: &[u8]) -> Result<LooseObject, String> {
    let (raw, used) =
        inflate_bounded(data, 256 * 1024 * 1024).map_err(|e| format!("loose 解压失败: {e}"))?;
    let nul = raw
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| "loose 头缺少 NUL 分隔".to_string())?;
    let header = std::str::from_utf8(&raw[..nul])
        .map_err(|_| "loose 头非 UTF-8".to_string())?;
    let (tname, size_s) = header
        .split_once(' ')
        .ok_or_else(|| "loose 头格式错误".to_string())?;
    let obj_type = ObjType::from_name(tname).ok_or_else(|| format!("未知类型 {tname}"))?;
    let declared_size: u64 = size_s
        .parse()
        .map_err(|_| "loose 头大小字段非法".to_string())?;
    let content = raw[nul + 1..].to_vec();
    if content.len() as u64 != declared_size {
        return Err(format!(
            "loose 大小欺骗: 头部声明 {declared_size} 实际 {}",
            content.len()
        ));
    }
    let oid = object_id(obj_type, &content);
    Ok(LooseObject {
        obj_type,
        declared_size,
        content,
        oid,
        compressed_len: used,
    })
}
