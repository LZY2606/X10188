pub mod delta;
pub mod engine;
pub mod error;
pub mod git;
pub mod idx;
pub mod importer;
pub mod loose;
pub mod pack;
pub mod queries;
pub mod resolver;
pub mod store;
pub mod web;
pub mod zlibm;

pub mod testing {
    use super::store::Store;
    use std::path::Path;

    pub fn open_readonly(dir: &Path) -> (rusqlite::Connection, Store) {
        Store::open(dir).unwrap()
    }
}
