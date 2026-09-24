use rusqlite::Connection;
use std::path::{Path, PathBuf};

pub struct Db {
    pub conn: Connection,
    pub data_dir: PathBuf,
}

impl Db {
    pub fn open(root: &Path) -> Result<Self, String> {
        std::fs::create_dir_all(root.join("data")).map_err(|e| e.to_string())?;
        let data_dir = root.join("data");
        let path = data_dir.join("microscope.sqlite");
        let mut conn = Connection::open(path).map_err(|e| e.to_string())?;
        conn.pragma_update(None, "foreign_keys", true).map_err(|e| e.to_string())?;
        conn.pragma_update(None, "busy_timeout", 5000).map_err(|e| e.to_string())?;
        migrate(&mut conn)?;
        Ok(Self { conn, data_dir })
    }

    pub fn memory() -> Result<Self, String> {
        let data_dir = std::env::temp_dir().join(format!(
            "pack-chain-microscope-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&data_dir).map_err(|e| e.to_string())?;
        let mut conn = Connection::open_in_memory().map_err(|e| e.to_string())?;
        conn.pragma_update(None, "foreign_keys", true).map_err(|e| e.to_string())?;
        migrate(&mut conn)?;
        Ok(Self { conn, data_dir })
    }
}

fn migrate(conn: &mut Connection) -> Result<(), String> {
    conn.execute_batch(include_str!("../schema.sql")).map_err(|e| e.to_string())
}

pub fn now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    format!("{secs}")
}
