//! 共享类型：对象类型、解析错误码。

use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ObjectType {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
}

impl ObjectType {
    pub fn from_pack_code(code: u8) -> Option<ObjectType> {
        match code {
            1 => Some(ObjectType::Commit),
            2 => Some(ObjectType::Tree),
            3 => Some(ObjectType::Blob),
            4 => Some(ObjectType::Tag),
            6 => Some(ObjectType::OfsDelta),
            7 => Some(ObjectType::RefDelta),
            _ => None,
        }
    }

    pub fn pack_code(self) -> u8 {
        match self {
            ObjectType::Commit => 1,
            ObjectType::Tree => 2,
            ObjectType::Blob => 3,
            ObjectType::Tag => 4,
            ObjectType::OfsDelta => 6,
            ObjectType::RefDelta => 7,
        }
    }

    pub fn is_delta(self) -> bool {
        matches!(self, ObjectType::OfsDelta | ObjectType::RefDelta)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ObjectType::Commit => "commit",
            ObjectType::Tree => "tree",
            ObjectType::Blob => "blob",
            ObjectType::Tag => "tag",
            ObjectType::OfsDelta => "ofs-delta",
            ObjectType::RefDelta => "ref-delta",
        }
    }

    pub fn base_kind_str(self) -> Option<&'static str> {
        match self {
            ObjectType::Commit => Some("commit"),
            ObjectType::Tree => Some("tree"),
            ObjectType::Blob => Some("blob"),
            ObjectType::Tag => Some("tag"),
            _ => None,
        }
    }
}

impl Serialize for ObjectType {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(self.as_str())
    }
}

/// 解析 / 还原过程中可能出现的错误证据。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fault {
    BadMagic,
    UnsupportedVersion(u32),
    Truncated,
    InvalidTypeCode(u8),
    /// ofs-delta 负偏移指向 pack 起点之前
    OfsOutOfRange(i64),
    /// 指定偏移上没有对象头
    OfsNoObject(i64),
    ZlibError(String),
    /// zlib 结束后仍有额外字节
    TrailingZlibBytes(usize),
    /// 头部声明大小与实际解压字节数不一致（大小欺骗）
    SizeMismatch { declared: u64, actual: u64 },
    /// delta 指令越界 / 非法
    DeltaInstruction(String),
    /// delta 声明的目标大小与实际不符
    DeltaTargetSize { declared: u64, actual: u64 },
    DeltaBaseSize { declared: u64, actual: u64 },
    /// 重新计算的 oid 与预期不一致
    OidMismatch { expected: String, actual: String },
    /// pack 结尾校验和不匹配
    PackChecksumMismatch,
    /// idx 声称的 pack 与实际 pack 不配套
    IndexPackMismatch,
    /// idx CRC 校验失败
    IdxCrcMismatch { offset: u64, expected: u32, actual: u32 },
    /// 解压结果超过安全上限（疑似 zip bomb）
    Bomb(u64),
    LooseHeader(String),
}

impl Fault {
    pub fn code(&self) -> &'static str {
        match self {
            Fault::BadMagic => "bad_magic",
            Fault::UnsupportedVersion(_) => "unsupported_version",
            Fault::Truncated => "truncated",
            Fault::InvalidTypeCode(_) => "invalid_type_code",
            Fault::OfsOutOfRange(_) => "ofs_out_of_range",
            Fault::OfsNoObject(_) => "ofs_no_object",
            Fault::ZlibError(_) => "zlib_error",
            Fault::TrailingZlibBytes(_) => "trailing_zlib_bytes",
            Fault::SizeMismatch { .. } => "size_mismatch",
            Fault::DeltaInstruction(_) => "delta_instruction",
            Fault::DeltaTargetSize { .. } => "delta_target_size",
            Fault::DeltaBaseSize { .. } => "delta_base_size",
            Fault::OidMismatch { .. } => "oid_mismatch",
            Fault::PackChecksumMismatch => "pack_checksum_mismatch",
            Fault::IndexPackMismatch => "index_pack_mismatch",
            Fault::IdxCrcMismatch { .. } => "idx_crc_mismatch",
            Fault::Bomb(_) => "bomb",
            Fault::LooseHeader(_) => "loose_header",
        }
    }

    pub fn message(&self) -> String {
        match self {
            Fault::BadMagic => "魔数错误".into(),
            Fault::UnsupportedVersion(v) => format!("不支持的版本 {}", v),
            Fault::Truncated => "数据被截断".into(),
            Fault::InvalidTypeCode(c) => format!("非法对象类型码 {}", c),
            Fault::OfsOutOfRange(o) => format!("ofs-delta 负偏移越界: {}", o),
            Fault::OfsNoObject(o) => format!("ofs-delta 基偏移 {} 处没有对象", o),
            Fault::ZlibError(s) => format!("zlib 解压失败: {}", s),
            Fault::TrailingZlibBytes(n) => format!("zlib 流结束后多出 {} 字节", n),
            Fault::SizeMismatch { declared, actual } => format!(
                "大小欺骗: 头部声明 {} 字节, 实际解压 {} 字节",
                declared, actual
            ),
            Fault::DeltaInstruction(s) => format!("delta 指令错误: {}", s),
            Fault::DeltaTargetSize { declared, actual } => {
                format!("delta 目标大小声明 {} 实际 {}", declared, actual)
            }
            Fault::DeltaBaseSize { declared, actual } => {
                format!("delta 基大小声明 {} 实际 {}", declared, actual)
            }
            Fault::OidMismatch { expected, actual } => {
                format!("oid 不匹配: 期望 {} 实际 {}", expected, actual)
            }
            Fault::PackChecksumMismatch => "pack SHA-1 校验和不匹配".into(),
            Fault::IndexPackMismatch => "idx 与 pack 不配套".into(),
            Fault::IdxCrcMismatch {
                offset,
                expected,
                actual,
            } => format!(
                "idx CRC 不匹配 @{}: idx 记录 {:08x} 实际 {:08x}",
                offset, expected, actual
            ),
            Fault::Bomb(n) => format!("解压结果超过安全上限 ({} 字节)", n),
            Fault::LooseHeader(s) => format!("loose 对象头错误: {}", s),
        }
    }
}
