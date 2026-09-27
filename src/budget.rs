//! 资源预算：delta 深度、总展开字节、单对象比例与单对象绝对上限。
//!
//! 达到上限时返回 [`BudError::Paused`]，调用方必须把它视为“可重试的中间状态”，
//! 绝不能把已经产生的部分输出当作完整对象。

use serde::{Deserialize, Serialize};

/// 单个分析分支（branch）的资源预算。
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Budget {
    /// delta 链最大深度（base 对象深度为 0）。
    pub max_depth: u32,
    /// 整个分支允许累积展开的总字节数（每个还原对象的输出长度之和）。
    pub max_total_expanded: u64,
    /// 单个对象输出相对其“输入重量”的最大倍数。输入重量取最终非 delta
    /// base 与链上所有 delta 负载长度之和。
    pub max_obj_ratio: f64,
    /// 单个对象输出绝对上限（字节），0 表示使用默认硬上限。
    pub max_obj_abs: u64,
}

impl Default for Budget {
    fn default() -> Self {
        Budget {
            max_depth: 50,
            max_total_expanded: 64 * 1024 * 1024,
            max_obj_ratio: 100.0,
            max_obj_abs: 16 * 1024 * 1024,
        }
    }
}

/// 预算暂停原因（可重试）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Paused {
    /// delta 深度达到上限；携带尝试到达的深度。
    Depth { at: u32, limit: u32 },
    /// 分支累计展开字节达到上限。
    Total { needed: u64, used: u64, limit: u64 },
    /// 单对象输出超过输入重量允许的比例。
    Ratio { output: u64, input_weight: u64, ratio: f64, limit: f64 },
    /// 单对象输出超过绝对上限。
    Abs { output: u64, limit: u64 },
}

impl Paused {
    pub fn code(&self) -> &'static str {
        match self {
            Paused::Depth { .. } => "depth",
            Paused::Total { .. } => "total",
            Paused::Ratio { .. } => "ratio",
            Paused::Abs { .. } => "abs",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum BudError {
    Paused(Paused),
}

impl std::fmt::Display for BudError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BudError::Paused(p) => write!(f, "budget paused: {:?}", p),
        }
    }
}
impl std::error::Error for BudError {}

/// 分支内累计的预算使用量。
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct BudgetUse {
    pub total_expanded: u64,
}

impl BudgetUse {
    /// 开始展开某对象前检查：深度 + 预期输出是否会越界。
    pub fn check(
        &self,
        b: &Budget,
        depth: u32,
        input_weight: u64,
        projected_output: u64,
    ) -> Result<(), BudError> {
        if depth > b.max_depth {
            return Err(BudError::Paused(Paused::Depth { at: depth, limit: b.max_depth }));
        }
        let abs = if b.max_obj_abs == 0 {
            crate::HARD_INFLATE_CAP as u64
        } else {
            b.max_obj_abs
        };
        if projected_output > abs {
            return Err(BudError::Paused(Paused::Abs { output: projected_output, limit: abs }));
        }
        if b.max_obj_ratio.is_finite() && b.max_obj_ratio >= 0.0 && input_weight > 0 {
            let ratio = projected_output as f64 / input_weight as f64;
            if ratio > b.max_obj_ratio {
                return Err(BudError::Paused(Paused::Ratio {
                    output: projected_output,
                    input_weight,
                    ratio,
                    limit: b.max_obj_ratio,
                }));
            }
        }
        if self.total_expanded.saturating_add(projected_output) > b.max_total_expanded {
            return Err(BudError::Paused(Paused::Total {
                needed: projected_output,
                used: self.total_expanded,
                limit: b.max_total_expanded,
            }));
        }
        Ok(())
    }

    /// 对象成功展开后累加。
    pub fn add(&mut self, n: u64) {
        self.total_expanded = self.total_expanded.saturating_add(n);
    }
}
