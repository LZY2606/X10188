//! 全项目共享的核心数据类型。

use serde::{Deserialize, Serialize};

/// Git 对象类型（含 delta 基类型解析后只保留前四种）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GitType {
    Commit,
    Tree,
    Blob,
    Tag,
}

impl GitType {
    pub fn name(self) -> &'static str {
        match self {
            GitType::Commit => "commit",
            GitType::Tree => "tree",
            GitType::Blob => "blob",
            GitType::Tag => "tag",
        }
    }
    pub fn header(self) -> &'static [u8] {
        match self {
            GitType::Commit => b"commit",
            GitType::Tree => b"tree",
            GitType::Blob => b"blob",
            GitType::Tag => b"tag",
        }
    }
}

/// pack 内条目的原始类型（6/7 为 delta）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntryKind {
    Plain(GitType),
    OfsDelta,
    RefDelta,
}

impl EntryKind {
    pub fn from_pack_code(code: u8) -> Option<EntryKind> {
        match code {
            1 => Some(EntryKind::Plain(GitType::Commit)),
            2 => Some(EntryKind::Plain(GitType::Tree)),
            3 => Some(EntryKind::Plain(GitType::Blob)),
            4 => Some(EntryKind::Plain(GitType::Tag)),
            6 => Some(EntryKind::OfsDelta),
            7 => Some(EntryKind::RefDelta),
            _ => None,
        }
    }
}

/// 候选对象的来源定位（导入顺序无关）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ObjOrigin {
    /// pack 内对象：pack 源文件 + entry 起始偏移 + zlib 数据偏移 + zlib 长度
    PackEntry {
        source_id: i64,
        entry_offset: u64,
        zlib_offset: u64,
        zlib_len: u64,
    },
    /// loose object：source id
    Loose { source_id: i64 },
}

impl ObjOrigin {
    pub fn source_id(self) -> i64 {
        match self {
            ObjOrigin::PackEntry { source_id, .. } | ObjOrigin::Loose { source_id } => source_id,
        }
    }
    pub fn encode(self) -> String {
        serde_json::to_string(&self).unwrap()
    }
    pub fn decode(s: &str) -> Option<ObjOrigin> {
        serde_json::from_str(s).ok()
    }
}

/// 单条证据 / 错误记录。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub code: String,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
}

impl Evidence {
    pub fn new(code: impl Into<String>, detail: impl Into<String>) -> Self {
        Evidence { code: code.into(), detail: detail.into(), offset: None }
    }
    pub fn at(mut self, offset: u64) -> Self {
        self.offset = Some(offset);
        self
    }
    pub fn encode(list: &[Evidence]) -> String {
        serde_json::to_string(list).unwrap_or_else(|_| "[]".into())
    }
    pub fn decode(s: &str) -> Vec<Evidence> {
        serde_json::from_str(s).unwrap_or_default()
    }
}

/// 解析 / 还原的局部状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjState {
    /// 原始条目本身可解析（delta 基内容尚未还原也算）。
    Raw,
    /// 已还原并完成 sha1 校验。
    Resolved,
    /// 对象自身数据损坏（环、坏 CRC、大小欺骗、坏 delta 指令等）——不可重试。
    Corrupt,
    /// 缺外部 base 或依赖处于 corrupt/paused。
    Blocked,
    /// 触发资源预算，可重试。
    Paused,
}

impl ObjState {
    pub fn name(self) -> &'static str {
        match self {
            ObjState::Raw => "raw",
            ObjState::Resolved => "resolved",
            ObjState::Corrupt => "corrupt",
            ObjState::Blocked => "blocked",
            ObjState::Paused => "paused",
        }
    }
}

/// delta 应用的单步记录。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaStep {
    pub index: usize,
    /// base 的定位描述（source 与偏移 / oid）
    pub base: String,
    /// delta 指令在解压后 delta 数据内的 [start,end) 累计范围
    pub cmd_ranges: Vec<[u64; 2]>,
    pub input_len: u64,
    pub output_len: u64,
    pub base_size_declared: u64,
    pub result_size_declared: u64,
    pub verify: String,
}

/// 资源预算。
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Budget {
    /// delta 链最大深度（base 本身为深度 0）。
    pub max_depth: u32,
    /// 全部解压 / 展开字节总额。
    pub total_bytes: u64,
    /// 已消耗展开字节。
    pub spent_bytes: u64,
    /// 单个对象展开大小占总额的比例上限（0..=1）。
    pub per_object_ratio: f64,
}

impl Budget {
    pub const DEFAULT_MAX_DEPTH: u32 = 16;
    pub const DEFAULT_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
    pub const DEFAULT_RATIO: f64 = 0.5;

    pub fn defaults() -> Self {
        Budget {
            max_depth: Self::DEFAULT_MAX_DEPTH,
            total_bytes: Self::DEFAULT_TOTAL_BYTES,
            spent_bytes: 0,
            per_object_ratio: Self::DEFAULT_RATIO,
        }
    }

    pub fn per_object_cap(&self) -> u64 {
        ((self.total_bytes as f64) * self.per_object_ratio.clamp(0.0, 1.0)) as u64
    }

    pub fn remaining(&self) -> u64 {
        self.total_bytes.saturating_sub(self.spent_bytes)
    }

    /// 申请 `bytes` 字节预算；超过单对象上限或总额时返回 false（可重试中间状态）。
    pub fn request(&mut self, bytes: u64) -> bool {
        if bytes > self.per_object_cap() {
            return false;
        }
        match self.spent_bytes.checked_add(bytes) {
            Some(total) if total <= self.total_bytes => {
                self.spent_bytes = total;
                true
            }
            _ => false,
        }
    }
}
