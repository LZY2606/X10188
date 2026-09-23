use serde::{Deserialize, Serialize};

/// 资源预算：深度、总展开字节、单对象压缩比
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Budgets {
    pub max_depth: u32,
    pub max_total_bytes: u64,
    pub max_ratio: f64,
}

impl Default for Budgets {
    fn default() -> Self {
        Budgets {
            max_depth: 64,
            max_total_bytes: 256 * 1024 * 1024,
            max_ratio: 10000.0,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub enum BudgetHit {
    Depth { depth: u32, max: u32 },
    TotalBytes { used: u64, max: u64 },
    Ratio { ratio: f64, max: f64 },
}

impl BudgetHit {
    pub fn message(&self) -> String {
        match self {
            BudgetHit::Depth { depth, max } => format!("达到 delta 深度预算: {depth} >= {max}"),
            BudgetHit::TotalBytes { used, max } => {
                format!("达到总展开字节预算: {used} >= {max}")
            }
            BudgetHit::Ratio { ratio, max } => {
                format!("达到单对象展开比例预算: {ratio:.1} >= {max:.1}")
            }
        }
    }
}
