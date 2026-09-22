//! 贯穿整个取证管线的核心数据类型。

use serde::Serialize;

/// Git 已知对象类型。`Bad` 表示类型字段非法（仅可能出现在伪造 header 中）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjType {
    Commit,
    Tree,
    Blob,
    Tag,
    /// ofs-delta / ref-delta 只是“存储类型”，还原后会得到上面四种之一。
    OfsDelta,
    RefDelta,
    /// 类型 nibble 为 0 或 6/7 等保留值。
    Bad,
}

impl ObjType {
    pub fn from_nibble(n: u8) -> ObjType {
        match n {
            1 => ObjType::Commit,
            2 => ObjType::Tree,
            3 => ObjType::Blob,
            4 => ObjType::Tag,
            6 => ObjType::OfsDelta,
            7 => ObjType::RefDelta,
            _ => ObjType::Bad,
        }
    }

    /// 还原后对象类型用于 SHA1 摘要时的名称。
    pub fn git_name(self) -> Option<&'static str> {
        match self {
            ObjType::Commit => Some("commit"),
            ObjType::Tree => Some("tree"),
            ObjType::Blob => Some("blob"),
            ObjType::Tag => Some("tag"),
            _ => None,
        }
    }

    pub fn code(self) -> &'static str {
        match self {
            ObjType::Commit => "commit",
            ObjType::Tree => "tree",
            ObjType::Blob => "blob",
            ObjType::Tag => "tag",
            ObjType::OfsDelta => "ofs_delta",
            ObjType::RefDelta => "ref_delta",
            ObjType::Bad => "bad_type",
        }
    }
}

/// 取证过程中发现的一条“证据”：问题 + 原始字节范围（文件内偏移）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Evidence {
    /// 机器可读错误码，例如 `crc_mismatch`、`size_spoof`、`truncated_zlib`。
    pub code: String,
    /// 人类可读说明（中文）。
    pub message: String,
    /// 所属源文件中的字节偏移（绝对偏移）。
    pub offset: Option<u64>,
    /// 涉及的字节数。
    pub len: Option<u64>,
}

impl Evidence {
    pub fn new(code: &str, message: impl Into<String>, offset: Option<u64>, len: Option<u64>) -> Self {
        Evidence { code: code.to_string(), message: message.into(), offset, len }
    }
}

/// zlib 解压结果，同时保留压缩流边界，便于做 CRC 与“越界字节”取证。
#[derive(Debug, Clone)]
pub struct InflateOutcome {
    /// 解压得到的全部字节。
    pub data: Vec<u8>,
    /// 压缩流在输入中的起始偏移。
    pub comp_start: usize,
    /// 压缩流消耗的压缩字节数（下一个对象应从 comp_start + comp_len 开始）。
    pub comp_len: usize,
    /// 解压是否在流逻辑结束点处结束（zlib header + deflate + adler32 完整）。
    pub stream_finished: bool,
    /// 输入在流结束后是否还有未消费字节（正常 pack 中就是下一个对象）。
    pub trailing: usize,
}

/// pack 内一个对象条目的解析记录。delta 的引用信息单独存放。
#[derive(Debug, Clone, Serialize)]
pub struct PackEntry {
    /// 对象在 pack 文件中的绝对偏移（size 编码 header 的起点）。
    pub offset: u64,
    /// size+type 变长 header 占用的字节数。
    pub header_len: usize,
    /// header + delta 引用头（ofs/ref）总字节数；压缩数据紧随其后。
    pub meta_len: usize,
    /// 存储类型（含 delta）。
    pub stype: ObjType,
    /// header 中声明的解压后大小。
    pub declared_size: u64,
    /// 实际解压出的字节数。
    pub inflated_size: Option<u64>,
    /// zlib 压缩数据起点（绝对偏移）。
    pub comp_offset: u64,
    /// zlib 压缩流消耗的字节数。
    pub comp_len: Option<u64>,
    /// ofs-delta：base 的绝对偏移（相对编码已解码）。
    pub base_offset: Option<u64>,
    /// ref-delta：base 的 20 字节 oid（hex）。
    pub base_oid: Option<String>,
    /// 该条目自身的证据（CRC、大小欺骗、截断等）。
    pub evidence: Vec<Evidence>,
}

/// 整个 pack 文件的解析产物（header、trailer、条目布局全部保留）。
#[derive(Debug, Clone, Serialize)]
pub struct PackReport {
    pub version: u32,
    pub num_objects: u32,
    /// header 12 字节之后第一个对象的起点。
    pub data_start: u64,
    /// 实际扫出的条目（按偏移排序）。
    pub entries: Vec<PackEntry>,
    /// 文件尾部 20 字节 SHA1（hex）；若文件过短为 None。
    pub trailer_oid: Option<String>,
    /// 我们对 pack header+对象区（不含 trailer）重算的 SHA1。
    pub computed_checksum: Option<String>,
    /// pack 级别的证据（magic/version/trailer 错、无法继续扫描等）。
    pub evidence: Vec<Evidence>,
}

/// index v2 中一条对象记录。
#[derive(Debug, Clone, Serialize)]
pub struct IdxEntry {
    pub offset: u64,
    pub oid: String,
    /// crc32 期望值（index 记录的，针对压缩数据）。
    pub crc32: u32,
}

/// index 解析产物（重点是 fanout）。
#[derive(Debug, Clone, Serialize)]
pub struct IdxReport {
    pub version: u32,
    /// 256 个 fanout 桶；fanout[255] 即对象总数。
    pub fanout: Vec<u32>,
    pub entries: Vec<IdxEntry>,
    pub pack_checksum: Option<String>,
    pub idx_checksum: Option<String>,
    pub evidence: Vec<Evidence>,
}

/// loose object 解析产物。
#[derive(Debug, Clone, Serialize)]
pub struct LooseReport {
    pub oid: Option<String>,
    pub obj_type: ObjType,
    pub declared_size: u64,
    pub inflated_size: u64,
    pub body: Vec<u8>,
    pub evidence: Vec<Evidence>,
}
