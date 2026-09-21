use rusqlite::Connection;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub struct AppState {
    pub db: Mutex<Connection>,
    pub data_dir: PathBuf,
    pub files_dir: PathBuf,
    pub blobs_dir: PathBuf,
}

impl AppState {
    pub fn open(root: impl AsRef<Path>) -> rusqlite::Result<Self> {
        let root = root.as_ref().to_path_buf();
        let files_dir = root.join("files");
        let blobs_dir = root.join("blobs");
        std::fs::create_dir_all(&files_dir)
            .map_err(|err| rusqlite::Error::ToSqlConversionFailure(Box::new(err)))?;
        std::fs::create_dir_all(&blobs_dir)
            .map_err(|err| rusqlite::Error::ToSqlConversionFailure(Box::new(err)))?;
        let db = Connection::open(root.join("microscope.sqlite"))?;
        db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL;")?;
        let state = Self {
            db: Mutex::new(db),
            data_dir: root,
            files_dir,
            blobs_dir,
        };
        state.migrate()?;
        Ok(state)
    }

    fn migrate(&self) -> rusqlite::Result<()> {
        let db = self.db.lock().unwrap();
        db.execute_batch(include_str!("../schema.sql"))?;
        Ok(())
    }
}
