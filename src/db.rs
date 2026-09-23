//! SQLite persistence for imported sources, parsed entries, resolved
//! candidates, delta-step evidence, errors, conflict pins and run state.

use anyhow::Result;
use rusqlite::Connection;

pub fn open(path: &std::path::Path) -> Result<Connection> {
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.execute_batch(include_str!("schema.sql"))?;
    Ok(conn)
}

pub const BUDGET_KEYS: [(&str, i64); 3] = [
    ("max_depth", 50),
    ("max_total_bytes", 256 * 1024 * 1024),
    ("max_ratio", 1000),
];

pub fn ensure_defaults(conn: &Connection) -> Result<()> {
    for (k, v) in BUDGET_KEYS {
        conn.execute(
            "INSERT OR IGNORE INTO budgets(key, value) VALUES(?1, ?2)",
            rusqlite::params![k, v],
        )?;
    }
    conn.execute(
        "INSERT OR IGNORE INTO run_state(id, status, expanded_bytes, run_count) VALUES(1, 'idle', 0, 0)",
        [],
    )?;
    Ok(())
}
