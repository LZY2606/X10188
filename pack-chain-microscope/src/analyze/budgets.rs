use crate::db::{get_kv, set_kv, Connection};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Budgets {
    pub max_depth: u64,
    pub total_expansion_bytes: u64,
    pub single_object_ratio: f64,
}

impl Default for Budgets {
    fn default() -> Self {
        Budgets {
            max_depth: 50,
            total_expansion_bytes: 256 * 1024 * 1024,
            single_object_ratio: 0.5,
        }
    }
}

impl Budgets {
    pub fn load(conn: &Connection) -> Self {
        get_kv(conn, "budgets")
            .ok()
            .flatten()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, conn: &Connection) {
        if let Ok(v) = serde_json::to_string(self) {
            set_kv(conn, "budgets", &v).ok();
        }
    }

    /// Maximum expanded size for a single object, derived from the global
    /// expansion budget and the per-object ratio.
    pub fn single_object_cap(&self) -> u64 {
        (self.total_expansion_bytes as f64 * self.single_object_ratio) as u64
    }
}
