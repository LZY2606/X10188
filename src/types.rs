use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ObjType {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
}

impl ObjType {
    pub fn from_pack_code(c: u8) -> Option<ObjType> {
        match c {
            1 => Some(ObjType::Commit),
            2 => Some(ObjType::Tree),
            3 => Some(ObjType::Blob),
            4 => Some(ObjType::Tag),
            6 => Some(ObjType::OfsDelta),
            7 => Some(ObjType::RefDelta),
            _ => None,
        }
    }

    pub fn is_delta(self) -> bool {
        matches!(self, ObjType::OfsDelta | ObjType::RefDelta)
    }

    pub fn loose_name(self) -> Option<&'static str> {
        match self {
            ObjType::Commit => Some("commit"),
            ObjType::Tree => Some("tree"),
            ObjType::Blob => Some("blob"),
            ObjType::Tag => Some("tag"),
            _ => None,
        }
    }

    pub fn from_loose_name(s: &str) -> Option<ObjType> {
        match s {
            "commit" => Some(ObjType::Commit),
            "tree" => Some(ObjType::Tree),
            "blob" => Some(ObjType::Blob),
            "tag" => Some(ObjType::Tag),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            ObjType::Commit => "commit",
            ObjType::Tree => "tree",
            ObjType::Blob => "blob",
            ObjType::Tag => "tag",
            ObjType::OfsDelta => "ofs-delta",
            ObjType::RefDelta => "ref-delta",
        }
    }
}

impl fmt::Display for ObjType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Why a node cannot currently be fully restored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FailReason {
    CorruptPack(String),
    InflateError(String),
    SizeSpoof { declared: u64, actual: u64 },
    CrcMismatch { expected: u32, actual: u32 },
    BadDelta(String),
    Cycle(Vec<String>),
    MissingBase(String),
    MissingBaseByOffset(u64),
    BaseFailed(String),
    OidMismatch { expected: String, computed: String },
    DepthLimit(usize),
    BudgetTotal(u64),
    BudgetRatio(f64),
    Conflict(String),
}

impl FailReason {
    pub fn code(&self) -> &'static str {
        match self {
            FailReason::CorruptPack(_) => "corrupt_pack",
            FailReason::InflateError(_) => "inflate_error",
            FailReason::SizeSpoof { .. } => "size_spoof",
            FailReason::CrcMismatch { .. } => "crc_mismatch",
            FailReason::BadDelta(_) => "bad_delta",
            FailReason::Cycle(_) => "cycle",
            FailReason::MissingBase(_) => "missing_base",
            FailReason::MissingBaseByOffset(_) => "missing_ofs_base",
            FailReason::BaseFailed(_) => "base_failed",
            FailReason::OidMismatch { .. } => "oid_mismatch",
            FailReason::DepthLimit(_) => "depth_limit",
            FailReason::BudgetTotal(_) => "budget_total",
            FailReason::BudgetRatio(_) => "budget_ratio",
            FailReason::Conflict(_) => "conflict",
        }
    }

    pub fn retryable(&self) -> bool {
        matches!(
            self,
            FailReason::DepthLimit(_)
                | FailReason::BudgetTotal(_)
                | FailReason::BudgetRatio(_)
                | FailReason::MissingBase(_)
                | FailReason::MissingBaseByOffset(_)
        )
    }

    pub fn describe(&self) -> String {
        match self {
            FailReason::CorruptPack(s) => format!("pack 结构损坏: {s}"),
            FailReason::InflateError(s) => format!("zlib 解压失败: {s}"),
            FailReason::SizeSpoof { declared, actual } => {
                format!("大小欺骗: header 声明 {declared} 字节，实际解压 {actual} 字节")
            }
            FailReason::CrcMismatch { expected, actual } => {
                format!("CRC32 校验失败: index={expected:08x} 实际={actual:08x}")
            }
            FailReason::BadDelta(s) => format!("delta 指令错误: {s}"),
            FailReason::Cycle(path) => format!("delta 形成环: {}", path.join(" -> ")),
            FailReason::MissingBase(oid) => format!("缺少外部 base: {oid}"),
            FailReason::MissingBaseByOffset(off) => format!("ofs-delta 越界: {off} 处没有对象"),
            FailReason::BaseFailed(s) => format!("base 还原失败: {s}"),
            FailReason::OidMismatch { expected, computed } => {
                format!("重算 oid 不匹配: index={expected} 实际={computed}")
            }
            FailReason::DepthLimit(d) => format!("预算暂停: delta 深度超过 {d}"),
            FailReason::BudgetTotal(b) => format!("预算暂停: 总展开字节超过 {b}"),
            FailReason::BudgetRatio(r) => format!("预算暂停: 单对象展开比例超过 {r}"),
            FailReason::Conflict(s) => format!("候选冲突: {s}"),
        }
    }

    pub fn to_json(&self) -> String {
        use std::fmt::Write;
        let esc = |s: &str| -> String {
            let mut out = String::with_capacity(s.len() + 2);
            for c in s.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c if (c as u32) < 0x20 => {
                        let _ = write!(out, "\\u{:04x}", c as u32);
                    }
                    c => out.push(c),
                }
            }
            out
        };
        match self {
            FailReason::CorruptPack(s) => format!(r#"{{"code":"corrupt_pack","detail":"{}"}}"#, esc(s)),
            FailReason::InflateError(s) => format!(r#"{{"code":"inflate_error","detail":"{}"}}"#, esc(s)),
            FailReason::SizeSpoof { declared, actual } => {
                format!(r#"{{"code":"size_spoof","declared":{declared},"actual":{actual}}}"#)
            }
            FailReason::CrcMismatch { expected, actual } => {
                format!(r#"{{"code":"crc_mismatch","expected":"{expected:08x}","actual":"{actual:08x}"}}"#)
            }
            FailReason::BadDelta(s) => format!(r#"{{"code":"bad_delta","detail":"{}"}}"#, esc(s)),
            FailReason::Cycle(path) => {
                let items: Vec<String> = path.iter().map(|p| format!(r#""{}""#, esc(p))).collect();
                format!(r#"{{"code":"cycle","path":[{}]}}"#, items.join(","))
            }
            FailReason::MissingBase(oid) => format!(r#"{{"code":"missing_base","oid":"{oid}"}}"#),
            FailReason::MissingBaseByOffset(off) => {
                format!(r#"{{"code":"missing_ofs_base","offset":{off}}}"#)
            }
            FailReason::BaseFailed(s) => format!(r#"{{"code":"base_failed","detail":"{}"}}"#, esc(s)),
            FailReason::OidMismatch { expected, computed } => {
                format!(r#"{{"code":"oid_mismatch","expected":"{expected}","computed":"{computed}"}}"#)
            }
            FailReason::DepthLimit(d) => format!(r#"{{"code":"depth_limit","depth":{d}}}"#),
            FailReason::BudgetTotal(b) => format!(r#"{{"code":"budget_total","bytes":{b}}}"#),
            FailReason::BudgetRatio(r) => format!(r#"{{"code":"budget_ratio","ratio":{r}}}"#),
            FailReason::Conflict(s) => format!(r#"{{"code":"conflict","detail":"{}"}}"#, esc(s)),
        }
    }

    pub fn from_json(s: &str) -> Option<FailReason> {
        fn field<'a>(s: &'a str, key: &str) -> Option<&'a str> {
            let pat = format!("\"{key}\":");
            let i = s.find(&pat)? + pat.len();
            let rest = &s[i..];
            let c = rest.chars().next()?;
            if c == '"' {
                let end = rest[1..].find('"')? + 1;
                Some(&rest[1..end])
            } else {
                let end = rest
                    .find(|ch: char| ch == ',' || ch == '}')
                    .unwrap_or(rest.len());
                Some(rest[..end].trim())
            }
        }
        let code = field(s, "code")?;
        Some(match code {
            "corrupt_pack" => FailReason::CorruptPack(field(s, "detail").unwrap_or("").to_string()),
            "inflate_error" => FailReason::InflateError(field(s, "detail").unwrap_or("").to_string()),
            "size_spoof" => FailReason::SizeSpoof {
                declared: field(s, "declared").and_then(|v| v.parse().ok()).unwrap_or(0),
                actual: field(s, "actual").and_then(|v| v.parse().ok()).unwrap_or(0),
            },
            "crc_mismatch" => {
                let parse = |k: &str| {
                    field(s, k)
                        .and_then(|v| u32::from_str_radix(v, 16).ok())
                        .unwrap_or(0)
                };
                FailReason::CrcMismatch {
                    expected: parse("expected"),
                    actual: parse("actual"),
                }
            }
            "bad_delta" => FailReason::BadDelta(field(s, "detail").unwrap_or("").to_string()),
            "cycle" => {
                let inner = s
                    .split('[')
                    .nth(1)
                    .and_then(|p| p.split(']').next())
                    .unwrap_or("");
                let path = inner
                    .split(',')
                    .map(|x| x.trim().trim_matches('"').to_string())
                    .filter(|x| !x.is_empty())
                    .collect();
                FailReason::Cycle(path)
            }
            "missing_base" => FailReason::MissingBase(field(s, "oid").unwrap_or("").to_string()),
            "missing_ofs_base" => FailReason::MissingBaseByOffset(
                field(s, "offset").and_then(|v| v.parse().ok()).unwrap_or(0),
            ),
            "base_failed" => FailReason::BaseFailed(field(s, "detail").unwrap_or("").to_string()),
            "oid_mismatch" => FailReason::OidMismatch {
                expected: field(s, "expected").unwrap_or("").to_string(),
                computed: field(s, "computed").unwrap_or("").to_string(),
            },
            "depth_limit" => FailReason::DepthLimit(
                field(s, "depth").and_then(|v| v.parse().ok()).unwrap_or(0),
            ),
            "budget_total" => FailReason::BudgetTotal(
                field(s, "bytes").and_then(|v| v.parse().ok()).unwrap_or(0),
            ),
            "budget_ratio" => FailReason::BudgetRatio(
                field(s, "ratio").and_then(|v| v.parse().ok()).unwrap_or(0.0),
            ),
            "conflict" => FailReason::Conflict(field(s, "detail").unwrap_or("").to_string()),
            _ => return None,
        })
    }
}
