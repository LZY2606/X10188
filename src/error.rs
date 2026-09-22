use std::fmt;

/// 核心解析过程中可能出现的、带取证语义的错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PError {
    /// 文件过小，连最小头部都不完整。
    Truncated { what: String, at: usize, need: usize },
    /// 魔数/签名错误。
    BadSignature { what: String, sig: String },
    /// pack 版本不支持。
    UnsupportedPackVersion(u32),
    /// pack 声称的对象数与实际解析不符。
    ObjectCountMismatch { declared: u32, parsed: usize },
    /// 遇到未知/保留对象类型。
    UnknownType(u8),
    /// ofs-delta 的负向距离越界（落到 header 之前）。
    OfsOutOfBounds { at: u64, distance: u64 },
    /// 引用的包内偏移处没有对象。
    OfsNoEntry(u64),
    /// 压缩流损坏 / 提前结束。
    Zlib(String),
    /// 声明的 inflated 大小与实际解出的不一致（大小欺骗）。
    SizeSpoof { declared: u64, actual: u64 },
    /// 单个对象解出过大，硬上限（防 zip bomb）。
    InflateLimit { limit: u64, actual: u64 },
    /// delta 指令非法（copy 越界 / 保留 opcode 等）。
    Delta(String),
    /// loose 对象头非法。
    LooseHeader(String),
    /// 解析过程越过文件尾。
    Bounds(String),
    /// SHA-1 尾部校验失败。
    ChecksumMismatch { expected: String, actual: String },
    /// index 与 pack 不配套。
    IndexMismatch(String),
    /// index CRC32 与对象实际压缩数据不符。
    CrcMismatch { offset: u64, expected: u32, actual: u32 },
    /// 其它 IO 类错误。
    Io(String),
}

impl fmt::Display for PError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PError::Truncated { what, at, need } => write!(
                f,
                "文件截断：{} 在偏移 {} 需要 {} 字节",
                what, at, need
            ),
            PError::BadSignature { what, sig } => {
                write!(f, "{} 签名错误：0x{}", what, sig)
            }
            PError::UnsupportedPackVersion(v) => write!(f, "不支持的 pack 版本 {}", v),
            PError::ObjectCountMismatch { declared, parsed } => write!(
                f,
                "对象数不匹配：header 声明 {}，实际解析 {}",
                declared, parsed
            ),
            PError::UnknownType(t) => write!(f, "未知对象类型 {}", t),
            PError::OfsOutOfBounds { at, distance } => write!(
                f,
                "ofs-delta 距离越界：位于 {} 的 delta 回溯 {} 字节",
                at, distance
            ),
            PError::OfsNoEntry(o) => write!(f, "ofs-delta 基址 {} 处没有对象", o),
            PError::Zlib(s) => write!(f, "zlib 解压失败：{}", s),
            PError::SizeSpoof { declared, actual } => write!(
                f,
                "大小欺骗：头声明 {} 字节，实际解出 {} 字节",
                declared, actual
            ),
            PError::InflateLimit { limit, actual } => write!(
                f,
                "解压超过硬上限：上限 {}，实际至少 {}",
                limit, actual
            ),
            PError::Delta(s) => write!(f, "delta 指令非法：{}", s),
            PError::LooseHeader(s) => write!(f, "loose 对象头非法：{}", s),
            PError::Bounds(s) => write!(f, "边界越界：{}", s),
            PError::ChecksumMismatch { expected, actual } => write!(
                f,
                "SHA-1 校验失败：期望 {}，实际 {}",
                expected, actual
            ),
            PError::IndexMismatch(s) => write!(f, "index 与 pack 不配套：{}", s),
            PError::CrcMismatch {
                offset,
                expected,
                actual,
            } => write!(
                f,
                "index CRC 不匹配（偏移 {}）：期望 {:08x}，实际 {:08x}",
                offset, expected, actual
            ),
            PError::Io(s) => write!(f, "IO 错误：{}", s),
        }
    }
}

impl std::error::Error for PError {}

impl PError {
    pub fn code(&self) -> &'static str {
        match self {
            PError::Truncated { .. } => "truncated",
            PError::BadSignature { .. } => "bad_signature",
            PError::UnsupportedPackVersion(_) => "bad_version",
            PError::ObjectCountMismatch { .. } => "count_mismatch",
            PError::UnknownType(_) => "unknown_type",
            PError::OfsOutOfBounds { .. } => "ofs_out_of_bounds",
            PError::OfsNoEntry(_) => "ofs_no_entry",
            PError::Zlib(_) => "zlib",
            PError::SizeSpoof { .. } => "size_spoof",
            PError::InflateLimit { .. } => "inflate_limit",
            PError::Delta(_) => "bad_delta",
            PError::LooseHeader(_) => "loose_header",
            PError::Bounds(_) => "bounds",
            PError::ChecksumMismatch { .. } => "checksum",
            PError::IndexMismatch(_) => "index_mismatch",
            PError::CrcMismatch { .. } => "crc_mismatch",
            PError::Io(_) => "io",
        }
    }
}
