use serde::Serialize;

use crate::oid::Oid;

/// Git 对象类型（提交态/非 delta）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjKind {
    Commit,
    Tree,
    Blob,
    Tag,
}

impl ObjKind {
    pub fn from_type_num(n: u8) -> Option<ObjKind> {
        match n {
            1 => Some(ObjKind::Commit),
            2 => Some(ObjKind::Tree),
            3 => Some(ObjKind::Blob),
            4 => Some(ObjKind::Tag),
            _ => None,
        }
    }

    pub fn from_word(w: &[u8]) -> Option<ObjKind> {
        match w {
            b"commit" => Some(ObjKind::Commit),
            b"tree" => Some(ObjKind::Tree),
            b"blob" => Some(ObjKind::Blob),
            b"tag" => Some(ObjKind::Tag),
            _ => None,
        }
    }

    pub fn word(&self) -> &'static str {
        match self {
            ObjKind::Commit => "commit",
            ObjKind::Tree => "tree",
            ObjKind::Blob => "blob",
            ObjKind::Tag => "tag",
        }
    }

    pub fn name(&self) -> &'static str {
        self.word()
    }
}

impl Serialize for ObjKind {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.word())
    }
}

/// pack 内条目的“物理”类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryType {
    Base(ObjKind),
    OfsDelta,
    RefDelta,
}

impl EntryType {
    pub fn label(&self) -> String {
        match self {
            EntryType::Base(k) => k.word().to_string(),
            EntryType::OfsDelta => "ofs-delta".to_string(),
            EntryType::RefDelta => "ref-delta".to_string(),
        }
    }
}

/// 一条 delta 指令在 delta 数据中的字节区间（取证用）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct OpRange {
    /// 指令起点（相对 delta 数据）。
    pub start: usize,
    /// 指令终点（不含）。
    pub end: usize,
    /// "copy" 或 "insert"。
    pub op: String,
}

/// 单步 delta 还原记录。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeltaStepRec {
    /// 应用前的 base 候选 id。
    pub base_cand: i64,
    /// 应用前 base 的逻辑 oid（若已知）。
    pub base_oid: Option<Oid>,
    /// delta 头声明的 base 长度。
    pub declared_base_len: u64,
    /// delta 头声明的目标长度。
    pub declared_result_len: u64,
    /// 参与应用的实际 base 长度。
    pub input_len: u64,
    /// 还原输出长度。
    pub output_len: u64,
    /// 指令总条数。
    pub op_count: usize,
    /// 指令区间（默认保留全部，数据量很小）。
    pub ops: Vec<OpRange>,
    /// 指令区间文本，便于页面展示：如 "12 copy + 3 insert"。
    pub summary: String,
    /// 输入长度是否与声明 base 长度一致。
    pub input_matches_declared: bool,
    /// 输出长度是否与声明目标长度一致。
    pub output_matches_declared: bool,
}

/// 资源预算。达到任一上限即返回“可重试的中间状态”。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Budget {
    /// 最大 delta 深度（base 对象深度为 0）。
    pub max_depth: u32,
    /// 本次分析允许展开的总字节数（每个完整对象只计一次）。
    pub total_bytes: u64,
    /// 单个对象链相对其声明结果大小允许的中间膨胀倍数（放大 1000 倍整数）。
    /// ratio_millis = 1000 表示不允许超过声明大小；典型取 4000（4 倍）。
    pub ratio_millis: u64,
}

impl Default for Budget {
    fn default() -> Self {
        Budget {
            max_depth: 50,
            total_bytes: 256 * 1024 * 1024,
            ratio_millis: 8000,
        }
    }
}

impl Budget {
    pub fn new(max_depth: u32, total_bytes: u64, ratio_millis: u64) -> Self {
        Budget {
            max_depth,
            total_bytes,
            ratio_millis,
        }
    }
}

// ---- 候选对象（逻辑）状态 ----
pub mod status {
    /// 尚未解析（等待分析）。
    pub const PENDING: &str = "pending";
    /// 解析中（递归栈上）。
    pub const RESOLVING: &str = "resolving";
    /// 完整还原且 git oid 与声称一致（或 loose/无 idx 时自证一致）。
    pub const RESOLVED: &str = "resolved";
    /// 永久坏对象（解压失败/大小欺骗/坏 delta/CRC 错误/oid 不符/环），已隔离。
    pub const BAD: &str = "bad";
    /// 缺少外部 base，等待补入。
    pub const MISSING_BASE: &str = "missing_base";
    /// 预算耗尽暂停，可重试。
    pub const PAUSED: &str = "paused";
    /// delta 深度超过预算（视为可重试：提高深度预算后可继续）。
    pub const DEPTH_LIMIT: &str = "depth_limit";

    pub fn all() -> [&'static str; 7] {
        [
            PENDING,
            RESOLVING,
            RESOLVED,
            BAD,
            MISSING_BASE,
            PAUSED,
            DEPTH_LIMIT,
        ]
    }

    /// 可重试（预算放开或补入 base 后重新分析）。
    pub fn retriable(s: &str) -> bool {
        matches!(s, PAUSED | DEPTH_LIMIT | MISSING_BASE | PENDING | RESOLVING)
    }
}
