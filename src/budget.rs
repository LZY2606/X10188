//! Resource budgets for delta resolution.
//!
//! Three independent limits are enforced:
//! * `max_depth`  – longest delta chain allowed.
//! * `total_bytes`– summed inflated bytes for the whole analysis run.
//! * `single_ratio`– one object's result may not exceed this fraction of the
//!   total-byte budget (a guard against one giant object starving the run).
//!
//! When a limit is hit the engine returns a *retryable paused* state: staged
//! intermediates are never promoted to complete objects.

use crate::error::{BudgetExceeded, BudgetKind, Error, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Budgets {
    pub max_depth: u32,
    /// Summed inflated bytes across the whole run (all stages).
    pub total_bytes: u64,
    /// Fraction (0..=1) of `total_bytes` a single result may occupy.
    pub single_ratio: f64,
    /// Maximum number of objects resolved in one run.
    pub max_objects: u32,
}

impl Default for Budgets {
    fn default() -> Self {
        Budgets {
            max_depth: 50,
            total_bytes: 256 * 1024 * 1024,
            single_ratio: 0.5,
            max_objects: 100_000,
        }
    }
}

impl Budgets {
    pub fn single_cap(&self) -> u64 {
        (self.total_bytes as f64 * self.single_ratio.clamp(0.0, 1.0)) as u64
    }

    pub fn check_single(&self, size: u64) -> Result<()> {
        if size > self.single_cap() {
            return Err(Error::Budget(BudgetExceeded {
                kind: BudgetKind::SingleObject,
                detail: format!(
                    "object size {size} exceeds single-object cap {} (ratio {})",
                    self.single_cap(),
                    self.single_ratio
                ),
            }));
        }
        Ok(())
    }
}

/// Live meter shared by one resolution run.
#[derive(Debug, Default)]
pub struct Meter {
    pub inflated_bytes: u64,
    pub objects: u32,
}

impl Meter {
    pub fn charge_bytes(&mut self, n: u64, b: &Budgets) -> Result<()> {
        self.inflated_bytes = self.inflated_bytes.saturating_add(n);
        if self.inflated_bytes > b.total_bytes {
            return Err(Error::Budget(BudgetExceeded {
                kind: BudgetKind::TotalBytes,
                detail: format!(
                    "total inflated {} > budget {}",
                    self.inflated_bytes, b.total_bytes
                ),
            }));
        }
        Ok(())
    }

    pub fn charge_object(&mut self, b: &Budgets) -> Result<()> {
        self.objects += 1;
        if self.objects > b.max_objects {
            return Err(Error::Budget(BudgetExceeded {
                kind: BudgetKind::MaxObjects,
                detail: format!("objects {} > max {}", self.objects, b.max_objects),
            }));
        }
        Ok(())
    }
}
