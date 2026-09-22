use crate::db;
use crate::git::{
    oid_hex, parse_oid, ObjectType, Oid,
};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[derive(Clone)]
pub struct AppState {
    pub conn: std::sync::Arc<Mutex<Connection>>,
    pub data_dir: PathBuf,
    pub hard_limit: usize,
}

#[derive(Debug, Clone)]
pub struct Node {
    pub id: String,
    pub source: String,
    pub kind: NodeKind,
    pub object_type: ObjectType,
    pub payload: Vec<u8>,
    pub expected_oid: Option<Oid>,
    pub parse_error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind { Loose, NonDelta, OfsDelta, RefDelta, Bad }

#[derive(Clone)]
struct ResolvedObject {
    oid: Oid,
    object_type: ObjectType,
    data: Vec<u8>,
    depth: usize,
    expanded: u64,
}

#[derive(Clone)]
struct Failure {
    reason: String,
    paused: bool,
    chain: Vec<String>,
    blocked_node: Option<String>,
    blocked_oid: Option<Oid>,
}

#[derive(Clone, Copy)]
struct Budget { total: u64, depth: usize, single: u64, ratio: u64 }

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

fn source_id(filename: &str, data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(filename.as_bytes());
    h.update([0]);
    h.update(data);
    hex::encode(h.finalize())
}

fn node_pack(source: &str, offset: u64) -> String { format!("pack:{source}:{offset}") }
fn node_loose(source: &str, oid: &Oid) -> String { format!("loose:{source}:{}", oid_hex(oid)) }

impl AppState {
    pub fn new(data_dir: PathBuf) -> rusqlite::Result<Self> {
        fs::create_dir_all(data_dir.join("files")).ok();
        let conn = db::connect(&data_dir.join("microscope.db"))?;
        Ok(Self { conn: std::sync::Arc::new(Mutex::new(conn)), data_dir, hard_limit: 64 * 1024 * 1024 })
    }

    pub fn import_bytes(&self, filename: &str, data: Vec<u8>) -> rusqlite::Result<String> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let id = source_id(filename, &data);
        let exists: bool = tx.query_row("SELECT 1 FROM sources WHERE source_id=?1", params![id], |_| Ok(())).is_ok();
        if !exists {
            let digest = sha256_hex(&data);
            let safe: String = filename.chars().map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.'|'-'|'_') { c } else { '_' }).collect();
            let stored = format!("files/{}-{}", &digest[..16], safe);
            fs::write(self.data_dir.join(&stored), &data).map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
            let order = db::next_import_order(&tx)?;
            let kind = detect_kind(filename, &data);
            tx.execute("INSERT INTO sources(source_id,filename,kind,sha256,size,stored_path,import_order) VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![id, filename, kind, digest, data.len() as i64, stored, order])?;
            rebuild_sources(&tx, self.data_dir.join("files"), self.hard_limit)?;
        }
        tx.commit()?;
        let state = self.clone();
        std::thread::spawn(move || { state.analyze_branch("default"); });
        Ok(id)
    }

    pub fn analyze_branch(&self, branch: &str) -> rusqlite::Result<String> {
        let mut conn = self.conn.lock().unwrap();
        analyze_locked(&mut conn, &self.data_dir, branch)
    }

    pub fn set_budget(&self, total: u64, depth: usize, single: u64, ratio: u64) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("UPDATE analysis_runs SET budget_total=?2,budget_depth=?3,budget_single=?4,budget_ratio=?5 WHERE branch_id='default'",
            params![total, depth as i64, single, ratio])?;
        for branch in list_branches(&conn) {
            conn.execute("UPDATE analysis_runs SET budget_total=?2,budget_depth=?3,budget_single=?4,budget_ratio=?5 WHERE branch_id=?1",
                params![branch, total, depth as i64, single, ratio])?;
        }
        Ok(())
    }

    pub fn pin_candidate(&self, oid: &str, node: &str) -> rusqlite::Result<String> {
        let branch = {
            let conn = self.conn.lock().unwrap();
            db::upsert_branch_pin(&conn, oid, node)?
        };
        self.analyze_branch(&branch)?;
        Ok(branch)
    }

    pub fn delete_source_dependents(&self, source: &str) -> rusqlite::Result<Vec<(String, String, String)>> {
        let conn = self.conn.lock().unwrap();
        let mut out = Vec::new();
        let mut stmt = conn.prepare("SELECT node, COALESCE(oid,''), status FROM resolved WHERE status!='complete' AND node LIKE ?1")?;
        let rows = stmt.query_map(params![format!("pack:{source}:%")], |r| Ok((r.get::<_,String>(0)?, r.get::<_,String>(1)?, r.get::<_,String>(2)?)))?;
        for row in rows.flatten() { out.push(row); }
        let mut stmt = conn.prepare("SELECT node, oid, 'candidate' FROM loose_objects WHERE source_id=?1")?;
        let rows = stmt.query_map(params![source], |r| Ok((r.get::<_,String>(0)?, r.get::<_,String>(1)?, r.get::<_,String>(2)?)))?;
        for row in rows.flatten() { out.push(row); }
        Ok(out)
    }

    pub fn delete_source(&self, source: &str, confirm: bool) -> rusqlite::Result<Vec<(String, String, String)>> {
        if !confirm { return self.delete_source_dependents(source); }
        let path: Option<String> = {
            let conn = self.conn.lock().unwrap();
            conn.query_row("SELECT stored_path FROM sources WHERE source_id=?1", params![source], |r| r.get(0)).optional()?
        };
        if let Some(path) = path { let _ = fs::remove_file(self.data_dir.join(path)); }
        let mut conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM sources WHERE source_id=?1", params![source])?;
        db::clear_analysis_for_branch(&conn, "default")?;
        drop(conn);
        self.analyze_branch("default")?;
        Ok(vec![])
    }
}

fn detect_kind(filename: &str, data: &[u8]) -> &'static str {
    if data.starts_with(b"PACK") { "pack" }
    else if data.starts_with(b"\xfftOc") { "index" }
    else if filename.ends_with(".idx") { "index" }
    else if filename.ends_with(".pack") { "pack" }
    else { "loose" }
}

fn stored_bytes(data_dir: &Path, path: &str) -> Vec<u8> {
    fs::read(data_dir.join(path)).unwrap_or_default()
}

fn json_array(values: &[String]) -> String { crate::analyzer::json_public(values) }

fn expected_oid_from_path(filename: &str) -> Option<Oid> {
    let clean = filename.replace('\\', "/");
    let mut parts: Vec<&str> = clean.split('/').filter(|p| !p.is_empty()).collect();
    let file = parts.pop()?;
    let dir = parts.pop()?;
    if dir.len() == 2 && file.len() == 38 { parse_oid(&format!("{dir}{file}")) } else { None }
}

fn rebuild_sources(tx: &Connection, files_dir: PathBuf, hard_limit: usize) -> rusqlite::Result<()> {
    tx.execute("DELETE FROM loose_objects", [])?;
    tx.execute("DELETE FROM entries", [])?;
    tx.execute("DELETE FROM index_records", [])?;
    tx.execute("DELETE FROM indexes", [])?;
    tx.execute("DELETE FROM packs", [])?;

    let mut files: Vec<(String, String, String, i64, Vec<u8>)> = Vec::new();
    {
        let mut stmt = tx.prepare("SELECT source_id,filename,kind,import_order,stored_path FROM sources ORDER BY import_order")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,i64>(4)?,r.get::<_,String>(3)?)))?;
        for row in rows.flatten() {
            let bytes = fs::read(files_dir.join(&row.4)).unwrap_or_default();
            files.push((row.0,row.1,row.2,row.3,bytes));
        }
    }

    let mut indexes = Vec::new();
    let mut packs = Vec::new();
    for (id, _filename, kind, _order, bytes) in &files {
        if kind == "index" { indexes.push((id.clone(), crate::pack::parse_index(bytes.clone()))); }
        if kind == "pack" { packs.push((id.clone(), bytes)); }
    }
    for (id, index) in &indexes {
        let linked = index.pack_checksum.and_then(|checksum| packs.iter().find(|(_,bytes)| bytes.len()>=20 && <&[u8;20]>::try_from(&bytes[bytes.len()-20..]).map(|v| v == &checksum).unwrap_or(false)).map(|(id,_)| id.clone()));
        let pack = linked.as_ref().and_then(|pack_id| files.iter().find(|(id,_,kind,_,_)| id == pack_id && kind == "pack").map(|x| x.4.clone()));
        let hints = linked.as_ref().map(|_| index.records.iter().map(|r| r.offset).collect::<BTreeSet<_>>()).unwrap_or_default();
        tx.execute("INSERT INTO indexes(source_id,record_count,pack_checksum,index_checksum,fanout,parse_errors,pack_source_id) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![id,index.records.len() as i64,index.pack_checksum.map(|o| oid_hex(&o)),index.index_checksum.map(|o| oid_hex(&o)),json_array(&index.fanout.iter().map(|v| v.to_string()).collect::<Vec<_>>()),json_array(&index.errors),linked])?;
        for record in &index.records {
            tx.execute("INSERT INTO index_records(index_source,oid,offset,crc,crc_error) VALUES(?1,?2,?3,?4,NULL)",
                params![id,oid_hex(&record.oid),record.offset as i64,record.crc as i64])?;
        }
        if let Some(pack_bytes) = pack {
            for error in crate::pack::verify_index_crcs(&crate::pack::parse_pack(pack_bytes, &hints, hard_limit), index) {
                let (oid, offset) = error.split_whitespace().find_map(|w| parse_oid(w.trim_end_matches(','))).map(|o| (oid_hex(&o), -1i64)).unwrap_or_default();
                tx.execute("UPDATE index_records SET crc_error=?3 WHERE index_source=?1 AND oid=?2", params![id,oid,error])?;
            }
        }
    }
    for (id, bytes) in packs {
        let linked_index = indexes.iter().find(|(idx_id,_)| {
            tx.query_row::<Option<String>,_,_>("SELECT pack_source_id FROM indexes WHERE source_id=?1", params![idx_id], |r| r.get(0))
                .ok().flatten().as_deref() == Some(id.as_str())
        });
        let hints = linked_index.map(|(_,index)| index.records.iter().map(|r| r.offset).collect::<BTreeSet<_>>()).unwrap_or_default();
        let pack = crate::pack::parse_pack(bytes.clone(), &hints, hard_limit);
        let checksum = if bytes.len()>=20 { hex::encode(&bytes[bytes.len()-20..]) } else { String::new() };
        tx.execute("INSERT INTO packs(source_id,version,entry_count,checksum,parse_errors) VALUES(?1,?2,?3,?4,?5)",
            params![id,pack.version as i64,pack.declared_count as i64,checksum,json_array(&pack.parse_errors)])?;
        let expected = expected_map(tx, &id);
        for entry in pack.entries.values() {
            tx.execute("INSERT OR REPLACE INTO entries(node,pack_source,offset,header_end,compressed_start,compressed_end,type_code,type_name,declared_size,base_offset,base_oid,expected_oid,parse_error) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
                params![node_pack(&id,entry.offset),id,entry.offset as i64,entry.header_end as i64,entry.compressed_start as i64,entry.compressed_end as i64,entry.raw_type as i64,entry.object_type.name(),entry.declared_size as i64,entry.base_offset.map(|v| v as i64),entry.base_oid.as_ref().map(oid_hex),expected.get(&(entry.offset as i64)).map(oid_hex),entry.parse_error])?;
        }
    }
    for (id, filename, kind, _order, bytes) in files.into_iter().filter(|x| x.2 == "loose") {
        let expected = expected_oid_from_path(&filename).or_else(|| parse_oid(&filename));
        let object = crate::pack::parse_loose(&bytes, expected, hard_limit);
        let expected_oid = expected.unwrap_or(object.oid);
        let node = node_loose(&id, &expected_oid);
        tx.execute("INSERT INTO loose_objects(node,source_id,oid,type_name,size,parse_error) VALUES(?1,?2,?3,?4,?5,?6)",
            params![node,id,oid_hex(&object.oid),object.kind.name(),object.data.len() as i64,object.parse_error])?;
    }
    Ok(())
}

fn expected_map(conn: &Connection, pack_source: &str) -> BTreeMap<i64, Oid> {
    let mut out = BTreeMap::new();
    if let Ok(mut stmt) = conn.prepare("SELECT ir.offset,ir.oid FROM index_records ir JOIN indexes i ON ir.index_source=i.source_id WHERE i.pack_source_id=?1") {
        if let Ok(rows) = stmt.query_map(params![pack_source], |r| Ok((r.get::<_,i64>(0)?, r.get::<_,String>(1)?))) {
            for row in rows.flatten() { if let Some(oid) = parse_oid(&row.1) { out.insert(row.0, oid); } }
        }
    }
    out
}


fn analyze_locked(conn: &mut Connection, data_dir: &Path, branch: &str) -> rusqlite::Result<String> {
    crate::analyzer::analyze(conn, &data_dir.join("files"), branch)
}

fn list_branches(conn: &Connection) -> Vec<String> {
    crate::analyzer::list_branches(conn)
}
