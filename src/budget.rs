//! 资源预算：
//!   1. `max_depth`       —— 单条 delta 链最大深度；
//!   2. `max_total_bytes` —— 一次 resolve 运行中所有“新产出的目标字节”总和；
//!   3. `max_obj_ratio`   —— 单对象产出占总预算的最大比例（防单个巨型对象吃光预算），
//!                           同时设 `max_obj_bytes` 绝对上限。
//!
//! 超过任何一项都返回 `PauseReason`，resolver 必须把对象置为 `paused`（可重试），
//! 绝不能把半成品 output 落库成完整对象。

use serde::Serialize;

use crate::delta::{BudgetGuard, DeltaError};

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PauseReason {
    DepthLimit,
    TotalBudget,
    ObjectRatio,
    ObjectHardLimit,
}

impl PauseReason {
    pub fn code(self) -> &'static str {
        match self {
            PauseReason::DepthLimit => "depth_limit",
            PauseReason::TotalBudget => "total_budget_exceeded",
            PauseReason::ObjectRatio => "object_ratio_exceeded",
            PauseReason::ObjectHardLimit => "object_hard_limit",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            PauseReason::DepthLimit => "delta 深度超限",
            PauseReason::TotalBudget => "总展开字节预算耗尽",
            PauseReason::ObjectRatio => "单对象占用比例超限",
            PauseReason::ObjectHardLimit => "单对象绝对大小超限",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct BudgetConfig {
    pub max_depth: u32,
    pub max_total_bytes: u64,
    pub max_obj_ratio: f64,
    pub max_obj_bytes: u64,
}

impl Default for BudgetConfig {
    fn default() -> Self {
        BudgetConfig {
            max_depth: 20,
            max_total_bytes: 64 * 1024 * 1024,
            max_obj_ratio: 0.8,
            max_obj_bytes: 32 * 1024 * 1024,
        }
    }
}

/// 一次 resolve 运行的实时计数器。恢复/重试时以新的 RunGuard 重新执行，
/// 已经落库的成品字节计入 `used_total_base`（跨运行持久化）。
pub struct RunGuard {
    pub cfg: BudgetConfig,
    /// 本次运行新产出字节。
    pub used_this_run: u64,
    /// 进入本次运行前，已经完成对象占用的字节（持久值）。
    pub used_total_base: u64,
}

impl RunGuard {
    pub fn new(cfg: BudgetConfig, used_total_base: u64) -> Self {
        RunGuard { cfg, used_this_run: 0, used_total_base }
    }

    /// 对象上限 = min(绝对上限, 总预算 * 比例)。
    pub fn per_object_cap(&self) -> u64 {
        let ratio_cap = (self.cfg.max_total_bytes as f64 * self.cfg.max_obj_ratio) as u64;
        self.cfg.max_obj_bytes.min(ratio_cap)
    }

    fn check_depth(&self, depth: u32) -> Result<(), PauseReason> {
        if depth > self.cfg.max_depth {
            Err(PauseReason::DepthLimit)
        } else {
            Ok(())
        }
    }
}

impl BudgetGuard for RunGuard {
    fn check_target(&self, target_size: u64, depth: u32) -> Result<(), String> {
        self.check_depth(depth).map_err(|r| format!("{}（深度 {depth}）", r.label()))?;
        let cap = self.per_object_cap();
        if target_size > self.cfg.max_obj_bytes {
            return Err(format!(
                "{}：目标声明 {} 字节 > 绝对上限 {} 字节",
                PauseReason::ObjectHardLimit.label(),
                target_size,
                self.cfg.max_obj_bytes
            ));
        }
        if target_size > cap {
            return Err(format!(
                "{}：目标声明 {} 字节 > 单对象上限 {}（总预算 {} × 比例 {}）",
                PauseReason::ObjectRatio.label(),
                target_size,
                cap,
                self.cfg.max_total_bytes,
                self.cfg.max_obj_ratio
            ));
        }
        Ok(())
    }

    fn charge(&mut self, add: u64, produced: usize, depth: u32, at_op: usize) -> Result<(), DeltaError> {
        if depth > self.cfg.max_depth {
            return Err(DeltaError::BudgetExceeded {
                at_op,
                produced,
                reason: format!("{}（深度 {depth}）", PauseReason::DepthLimit.label()),
            });
        }
        let cap = self.per_object_cap();
        if produced as u64 + add > cap {
            return Err(DeltaError::BudgetExceeded {
                at_op,
                produced,
                reason: format!("{}（将产出 {}，单对象上限 {}）", PauseReason::ObjectRatio.label(), produced as u64 + add, cap),
            });
        }
        if self.used_total_base + self.used_this_run + add > self.cfg.max_total_bytes {
            return Err(DeltaError::BudgetExceeded {
                at_op,
                produced,
                reason: format!(
                    "{}（已用 {}+{}，再追加 {}，上限 {}）",
                    PauseReason::TotalBudget.label(),
                    self.used_total_base,
                    self.used_this_run,
                    add,
                    self.cfg.max_total_bytes
                ),
            });
        }
        self.used_this_run += add;
        Ok(())
    }
}
