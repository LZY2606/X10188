use crate::git::ObjType;
use crate::idx::{parse_idx, verify_entry_crc, ParsedIdx};
use crate::loose::parse_loose;
use crate::pack::{parse_pack_with_offsets, ParsedPack};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use sha2::{Digest, Sha256};

pub const SCHEMA_VERSION: i64 = 1;

pub fn open(path: &std::path::Path) -> rusqlite::Result<Connection> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    init_schema(&conn)?;
    Ok(conn)
}

pub fn init_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        r#"
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sources (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL CHECK(kind IN ('pack','idx','loose')),
  filename TEXT NOT NULL,
  stored_path TEXT NOT NULL,
  size INTEGER NOT NULL,
  sha256 TEXT NOT NULL UNIQUE,
  imported_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS packs (
  source_id INTEGER PRIMARY KEY REFERENCES sources(id) ON DELETE CASCADE,
  version INTEGER,
  object_count INTEGER,
  pack_sha TEXT,
  computed_pack_sha TEXT,
  checksum_ok INTEGER,
  parse_json TEXT NOT NULL,
  idx_id INTEGER REFERENCES sources(id) ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS idxs (
  source_id INTEGER PRIMARY KEY REFERENCES sources(id) ON DELETE CASCADE,
  pack_id INTEGER REFERENCES sources(id) ON DELETE SET NULL,
  pack_sha TEXT,
  idx_sha TEXT,
  checksum_ok INTEGER,
  fanout_json TEXT NOT NULL,
  parse_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS idx_entries (
  idx_id INTEGER NOT NULL REFERENCES idxs(source_id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  oid TEXT NOT NULL,
  offset INTEGER NOT NULL,
  crc32 INTEGER NOT NULL,
  PRIMARY KEY (idx_id, ordinal)
);
CREATE TABLE IF NOT EXISTS candidates (
  ckey TEXT PRIMARY KEY,
  source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  source_kind TEXT NOT NULL,
  oid TEXT,
  obj_type TEXT NOT NULL,
  offset INTEGER,
  end_offset INTEGER,
  declared_size INTEGER NOT NULL,
  actual_size INTEGER,
  ofs_distance INTEGER,
  ref_base TEXT,
  content BLOB,
  has_content INTEGER NOT NULL DEFAULT 0,
  crc_ok INTEGER,
  parse_error TEXT
);
CREATE INDEX IF NOT EXISTS idx_candidates_source ON candidates(source_id);
CREATE INDEX IF NOT EXISTS idx_candidates_oid ON candidates(oid);
CREATE TABLE IF NOT EXISTS issues (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source_id INTEGER REFERENCES sources(id) ON DELETE CASCADE,
  scope TEXT NOT NULL,
  severity TEXT NOT NULL,
  code TEXT NOT NULL,
  message TEXT NOT NULL,
  detail TEXT,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS branches (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS pins (
  branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
  oid TEXT NOT NULL,
  ckey TEXT NOT NULL,
  PRIMARY KEY (branch_id, oid)
);
CREATE TABLE IF NOT EXISTS budgets (
  branch_id INTEGER PRIMARY KEY REFERENCES branches(id) ON DELETE CASCADE,
  max_depth INTEGER NOT NULL,
  total_bytes INTEGER NOT NULL,
  single_ratio REAL NOT NULL,
  used_bytes INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS resolved (
  branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
  ckey TEXT NOT NULL,
  oid TEXT,
  status TEXT NOT NULL,
  obj_type TEXT,
  content BLOB,
  content_len INTEGER,
  depth INTEGER,
  charged_bytes INTEGER,
  reason TEXT,
  evidence TEXT,
  base_ckey TEXT,
  chain_json TEXT NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (branch_id, ckey)
);
CREATE TABLE IF NOT EXISTS steps (
  branch_id INTEGER NOT NULL,
  ordinal INTEGER NOT NULL,
  ckey TEXT NOT NULL,
  delta_kind TEXT,
  base_ckey TEXT,
  base_oid TEXT,
  input_len INTEGER,
  output_len INTEGER,
  instruction_start INTEGER,
  instruction_end INTEGER,
  copies INTEGER,
  inserts INTEGER,
  check_ok INTEGER,
  evidence TEXT,
  PRIMARY KEY (branch_id, ckey, ordinal)
);
CREATE TABLE IF NOT EXISTS relink (
  branch_id INTEGER NOT NULL,
  ckey TEXT NOT NULL,
  base_ckey TEXT NOT NULL,
  PRIMARY KEY (branch_id, ckey, base_ckey)
);
CREATE INDEX IF NOT EXISTS idx_relink_base ON relink(branch_id, base_ckey);
"#,
    )?;
    let exists: i64 = conn.query_row(
        "SELECT COUNT(*) FROM branches WHERE name='main'",
        [],
        |r| r.get(0),
    )?;
    if exists == 0 {
        conn.execute(
            "INSERT INTO branches(name, created_at) VALUES('main', ?)",
            params![now_ms()],
        )?;
        conn.execute(
            "INSERT INTO budgets(branch_id, max_depth, total_bytes, single_ratio, used_bytes)
             VALUES (1, ?, ?, ?, 0)",
            params![DEFAULT_MAX_DEPTH, DEFAULT_TOTAL_BYTES, DEFAULT_SINGLE_RATIO],
        )?;
    }
    conn.execute(
        "INSERT OR IGNORE INTO meta(key,value) VALUES('schema_version', ?)",
        params![SCHEMA_VERSION.to_string()],
    )?;
    Ok(())
}

pub const DEFAULT_MAX_DEPTH: i64 = 50;
pub const DEFAULT_TOTAL_BYTES: i64 = 64 * 1024 * 1024;
pub const DEFAULT_SINGLE_RATIO: f64 = 0.5;
pub const HARD_INFLATE_LIMIT: u64 = 64 * 1024 * 1024;
pub const LOOSE_HARD_LIMIT: u64 = 64 * 1024 * 1024;

pub fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

#[derive(Clone, Debug, Serialize)]
pub struct SourceRow {
    pub id: i64,
    pub kind: String,
    pub filename: String,
    pub size: i64,
    pub sha256: String,
    pub imported_at: i64,
}

pub fn list_sources(conn: &Connection) -> rusqlite::Result<Vec<SourceRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, kind, filename, size, sha256, imported_at
         FROM sources ORDER BY id",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(SourceRow {
            id: r.get(0)?,
            kind: r.get(1)?,
            filename: r.get(2)?,
            size: r.get(3)?,
            sha256: r.get(4)?,
            imported_at: r.get(5)?,
        })
    })?;
    rows.collect()
}

pub fn get_source_path(conn: &Connection, id: i64) -> rusqlite::Result<Option<String>> {
    conn.query_row("SELECT stored_path FROM sources WHERE id=?", params![id], |r| r.get(0))
        .optional()
}

#[derive(Clone, Debug)]
pub struct CandidateRow {
    pub ckey: String,
    pub source_id: i64,
    pub source_kind: String,
    pub oid: Option<String>,
    pub obj_type: String,
    pub offset: Option<i64>,
    pub end_offset: Option<i64>,
    pub declared_size: i64,
    pub actual_size: Option<i64>,
    pub ofs_distance: Option<i64>,
    pub ref_base: Option<String>,
    pub content: Option<Vec<u8>>,
    pub has_content: bool,
    pub crc_ok: Option<bool>,
    pub parse_error: Option<String>,
}

pub fn list_candidates(conn: &Connection) -> rusqlite::Result<Vec<CandidateRow>> {
    let mut stmt = conn.prepare(
        "SELECT ckey, source_id, source_kind, oid, obj_type, offset, end_offset,
                declared_size, actual_size, ofs_distance, ref_base, content, has_content, crc_ok, parse_error
         FROM candidates ORDER BY ckey",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(CandidateRow {
            ckey: r.get(0)?,
            source_id: r.get(1)?,
            source_kind: r.get(2)?,
            oid: r.get(3)?,
            obj_type: r.get(4)?,
            offset: r.get(5)?,
            end_offset: r.get(6)?,
            declared_size: r.get(7)?,
            actual_size: r.get(8)?,
            ofs_distance: r.get(9)?,
            ref_base: r.get(10)?,
            content: r.get(11)?,
            has_content: r.get::<_, i64>(12)? != 0,
            crc_ok: r.get::<_, Option<i64>>(13)?.map(|v| v != 0),
            parse_error: r.get(14)?,
        })
    })?;
    rows.collect()
}

pub struct ImportResult {
    pub source_id: i64,
    pub kind: String,
    pub duplicate: bool,
    pub affected_ck: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct PackBinding {
    pub idx_source_id: Option<i64>,
}

pub fn ckey_pack(source_hash: &str, offset: u64) -> String {
    format!("pack:{}:{:x}", source_hash, offset)
}
pub fn ckey_loose(source_hash: &str) -> String {
    format!("loose:{}", source_hash)
}

pub fn detect_kind(filename: &str, bytes: &[u8]) -> Option<&'static str> {
    if bytes.len() >= 4 && &bytes[0..4] == b"PACK" {
        return Some("pack");
    }
    if bytes.len() >= 8 && bytes[0..4] == [0xff, 0x74, 0x4f, 0x63] {
        return Some("idx");
    }
    let lower = filename.to_ascii_lowercase();
    if lower.ends_with(".pack") {
        return Some("pack");
    }
    if lower.ends_with(".idx") {
        return Some("idx");
    }
    Some("loose")
}

pub fn import_file(
    conn: &Connection,
    data_dir: &std::path::Path,
    filename: &str,
    bytes: &[u8],
) -> rusqlite::Result<ImportResult> {
    let kind = detect_kind(filename, bytes).unwrap_or("loose");
    let hash = sha256_hex(bytes);
    if let Some(id) = conn.query_row(
        "SELECT id FROM sources WHERE sha256=?",
        params![hash],
        |r| r.get::<_, i64>(0),
    ).optional()? {
        let affected = seed_affected(conn, id)?;
        return Ok(ImportResult {
            source_id: id,
            kind: kind.to_string(),
            duplicate: true,
            affected_ck: affected,
        });
    }
    let stored_dir = data_dir.join("files");
    std::fs::create_dir_all(&stored_dir).ok();
    let safe = filename
        .replace(['/', '\\', ':', ' '], "_")
        .chars()
        .take(120)
        .collect::<String>();
    let stored_name = format!("{}-{}", &hash[..16], safe);
    let stored_path = stored_dir.join(&stored_name);
    std::fs::write(&stored_path, bytes).ok();
    let ts = now_ms();
    conn.execute(
        "INSERT INTO sources(kind, filename, stored_path, size, sha256, imported_at)
         VALUES(?, ?, ?, ?, ?, ?)",
        params![kind, filename, stored_path.to_string_lossy(), bytes.len() as i64, hash, ts],
    )?;
    let source_id = conn.last_insert_rowid();
    let mut affected: Vec<String> = Vec::new();
    match kind {
        "pack" => {
            import_pack(conn, source_id, bytes, &hash)?;
            affected = seed_affected(conn, source_id)?;
        }
        "idx" => {
            import_idx(conn, data_dir, source_id, bytes)?;
            if let Some(pid) = conn
                .query_row(
                    "SELECT pack_id FROM idxs WHERE source_id=?",
                    params![source_id],
                    |r| r.get::<_, Option<i64>>(0),
                )
                .ok()
                .flatten()
            {
                rebind_pack_idx(conn, data_dir, pid, source_id)?;
                affected.extend(seed_affected(conn, pid)?);
            }
        }
        _ => {
            import_loose(conn, source_id, bytes, &hash)?;
            affected = seed_affected(conn, source_id)?;
        }
    }
    let unique: std::collections::BTreeSet<String> = affected.into_iter().collect();
    Ok(ImportResult {
        source_id,
        kind: kind.to_string(),
        duplicate: false,
        affected_ck: unique.into_iter().collect(),
    })
}

fn add_issue(
    conn: &Connection,
    source_id: Option<i64>,
    scope: &str,
    severity: &str,
    code: &str,
    message: &str,
    detail: Option<String>,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO issues(source_id, scope, severity, code, message, detail, created_at)
         VALUES(?, ?, ?, ?, ?, ?, ?)",
        params![source_id, scope, severity, code, message, detail, now_ms()],
    )?;
    Ok(())
}

fn import_pack(conn: &Connection, source_id: i64, bytes: &[u8], hash: &str) -> rusqlite::Result<()> {
    let idx_info = find_matching_idx(conn, bytes);
    let known_offsets: Option<Vec<u64>> = idx_info.as_ref().map(|(_, parsed)| {
        parsed.entries.iter().map(|e| e.offset).collect::<Vec<_>>()
    });
    let parsed: ParsedPack = parse_pack_with_offsets(
        bytes,
        known_offsets.as_deref(),
        Some(HARD_INFLATE_LIMIT),
    );
    if let Some(msg) = &parsed.header_issue {
        add_issue(conn, Some(source_id), "pack", "fatal", "pack_header", msg, None)?;
    }
    if parsed.checksum_ok == Some(false) {
        add_issue(
            conn,
            Some(source_id),
            "pack",
            "error",
            "pack_checksum",
            "pack 尾部 SHA1 与内容重算结果不一致",
            Some(serde_json::json!({
                "stored": parsed.pack_sha.map(hex::encode),
                "computed": parsed.computed_pack_sha.map(hex::encode),
            }).to_string()),
        )?;
    }
    for msg in &parsed.errors {
        add_issue(conn, Some(source_id), "pack", "error", "resync", msg, None)?;
    }
    if parsed.trailing_after_entries > 0 {
        add_issue(
            conn,
            Some(source_id),
            "pack",
            "warning",
            "trailing_bytes",
            &format!("对象区之后仍有 {} 字节", parsed.trailing_after_entries),
            None,
        )?;
    }
    let idx_id = idx_info.as_ref().map(|(id, _)| *id);
    let idx_by_offset: std::collections::HashMap<u64, &crate::idx::IdxEntry> = match &idx_info {
        Some((_, p)) => p.entries.iter().map(|e| (e.offset, e)).collect(),
        None => std::collections::HashMap::new(),
    };
    let pack_bytes_for_crc = bytes;
    for e in &parsed.entries {
        let ckey = ckey_pack(hash, e.offset);
        let oid = idx_by_offset.get(&e.offset).map(|ie| hex::encode(ie.oid));
        if let Some(ie) = idx_by_offset.get(&e.offset) {
            let end = e.next_offset.unwrap_or(e.offset);
            let ok = verify_entry_crc(pack_bytes_for_crc, e.offset, end, ie.crc32);
            if !ok {
                add_issue(
                    conn,
                    Some(source_id),
                    "candidate",
                    "error",
                    "crc_mismatch",
                    &format!("offset {} 的 idx CRC32 与 pack 字节不符", e.offset),
                    Some(serde_json::json!({"expected": ie.crc32, "offset": e.offset}).to_string()),
                )?;
            }
        }
        let crc_ok = idx_by_offset.get(&e.offset).map(|ie| {
            verify_entry_crc(
                pack_bytes_for_crc,
                e.offset,
                e.next_offset.unwrap_or(e.offset),
                ie.crc32,
            )
        });
        let typ = ObjType::named(e.obj_type).unwrap_or(ObjType::Blob);
        let (content, has_content) = match &e.data {
            Some(d) => (Some(d.clone()), true),
            None => (None, false),
        };
        conn.execute(
            "INSERT INTO candidates(ckey, source_id, source_kind, oid, obj_type, offset, end_offset,
                 declared_size, actual_size, ofs_distance, ref_base, content, has_content, crc_ok, parse_error)
             VALUES(?1,?2,'pack',?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
            params![
                ckey,
                source_id,
                oid,
                typ.type_name(),
                e.offset as i64,
                e.next_offset.map(|v| v as i64),
                e.declared_size as i64,
                e.data_len as i64,
                e.ofs_distance.map(|v| v as i64),
                e.ref_base.map(hex::encode),
                content,
                has_content as i64,
                crc_ok.map(|v| v as i64),
                e.error,
            ],
        )?;
        if let Some(err) = &e.error {
            add_issue(
                conn,
                Some(source_id),
                "candidate",
                "error",
                "entry_inflate",
                &format!("offset {}: {}", e.offset, err),
                Some(ckey),
            )?;
        }
    }
    let json = serde_json::to_string(&parsed).unwrap_or_default();
    conn.execute(
        "INSERT INTO packs(source_id, version, object_count, pack_sha, computed_pack_sha, checksum_ok, parse_json, idx_id)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
        params![
            source_id,
            parsed.version as i64,
            parsed.count as i64,
            parsed.pack_sha.map(hex::encode),
            parsed.computed_pack_sha.map(hex::encode),
            parsed.checksum_ok.map(|v| v as i64),
            json,
            idx_id,
        ],
    )?;
    if let Some((idx_src, _)) = &idx_info {
        conn.execute("UPDATE idxs SET pack_id=?1 WHERE source_id=?2", params![source_id, idx_src])?;
    }
    Ok(())
}

fn read_source_bytes(conn: &Connection, data_dir: &std::path::Path, id: i64) -> Option<Vec<u8>> {
    let rel: String = conn
        .query_row("SELECT stored_path FROM sources WHERE id=?", params![id], |r| r.get(0))
        .ok()?;
    let p = std::path::Path::new(&rel);
    let path = if p.is_absolute() {
        p.to_path_buf()
    } else {
        data_dir.join(p)
    };
    std::fs::read(path).ok()
}

fn find_matching_idx(conn: &Connection, pack_bytes: &[u8]) -> Option<(i64, ParsedIdx)> {
    let mut stmt = conn
        .prepare("SELECT s.id, s.stored_path FROM sources s JOIN idxs i ON i.source_id=s.id")
        .ok()?;
    let ids: Vec<(i64, String)> = stmt
        .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))
        .ok()?
        .filter_map(|r| r.ok())
        .collect();
    let stored = &pack_bytes[pack_bytes.len() - 20..];
    for (id, path) in ids {
        if let Ok(bytes) = std::fs::read(&path) {
            let parsed = parse_idx(&bytes);
            if parsed.pack_sha.as_ref().map(|a| &a[..]) == Some(stored) {
                return Some((id, parsed));
            }
        }
    }
    None
}

fn import_idx(
    conn: &Connection,
    _data_dir: &std::path::Path,
    source_id: i64,
    bytes: &[u8],
) -> rusqlite::Result<()> {
    let parsed = parse_idx(bytes);
    for msg in &parsed.errors {
        add_issue(conn, Some(source_id), "idx", "error", "idx_parse", msg, None)?;
    }
    if parsed.checksum_ok == Some(false) {
        add_issue(
            conn,
            Some(source_id),
            "idx",
            "error",
            "idx_checksum",
            "idx 尾部 SHA1 与内容重算结果不一致",
            Some(serde_json::json!({
                "stored": parsed.idx_sha.map(hex::encode),
                "computed": parsed.computed_idx_sha.map(hex::encode),
            }).to_string()),
        )?;
    }
    let pack_id: Option<i64> = conn
        .query_row(
            "SELECT p.source_id FROM packs p
             WHERE p.pack_sha = ?1",
            params![parsed.pack_sha.map(hex::encode)],
            |r| r.get(0),
        )
        .optional()?;
    let fanout_json = serde_json::to_string(&parsed.fanout).unwrap_or_default();
    let parse_json = serde_json::to_string(&parsed).unwrap_or_default();
    conn.execute(
        "INSERT INTO idxs(source_id, pack_id, pack_sha, idx_sha, checksum_ok, fanout_json, parse_json)
         VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![
            source_id,
            pack_id,
            parsed.pack_sha.map(hex::encode),
            parsed.idx_sha.map(hex::encode),
            parsed.checksum_ok.map(|v| v as i64),
            fanout_json,
            parse_json,
        ],
    )?;
    for (i, e) in parsed.entries.iter().enumerate() {
        conn.execute(
            "INSERT INTO idx_entries(idx_id, ordinal, oid, offset, crc32)
             VALUES(?1,?2,?3,?4,?5)",
            params![source_id, i as i64, hex::encode(e.oid), e.offset as i64, e.crc32 as i64],
        )?;
    }
    Ok(())
}

fn rebind_pack_idx(
    conn: &Connection,
    data_dir: &std::path::Path,
    pack_source_id: i64,
    idx_source_id: i64,
) -> rusqlite::Result<()> {
    let pack_bytes = match read_source_bytes(conn, data_dir, pack_source_id) {
        Some(b) => b,
        None => return Ok(()),
    };
    let idx_bytes = match read_source_bytes(conn, data_dir, idx_source_id) {
        Some(b) => b,
        None => return Ok(()),
    };
    let parsed_idx = parse_idx(&idx_bytes);
    conn.execute(
        "UPDATE packs SET idx_id=?1 WHERE source_id=?2",
        params![idx_source_id, pack_source_id],
    )?;
    for (ord, ie) in parsed_idx.entries.iter().enumerate() {
        let oid_hex = hex::encode(ie.oid);
        let ckey = conn.query_row(
            "SELECT ckey FROM candidates
             WHERE source_id=?1 AND source_kind='pack' AND offset=?2",
            params![pack_source_id, ie.offset as i64],
            |r| r.get::<_, String>(0),
        ).optional()?;
        let ckey = match ckey {
            Some(k) => k,
            None => continue,
        };
        let end: Option<i64> = conn.query_row(
            "SELECT end_offset FROM candidates WHERE ckey=?",
            params![ckey],
            |r| r.get(0),
        ).optional()?;
        let crc_ok = match end {
            Some(end) => Some(verify_entry_crc(&pack_bytes, ie.offset, end as u64, ie.crc32) as i64),
            None => None,
        };
        conn.execute(
            "UPDATE candidates SET oid=?1, crc_ok=?2 WHERE ckey=?3",
            params![oid_hex, crc_ok, ckey],
        )?;
        if crc_ok == Some(0) {
            add_issue(
                conn,
                Some(pack_source_id),
                "candidate",
                "error",
                "crc_mismatch",
                &format!("绑定 idx（第 {} 项）后发现 offset {} CRC32 不符", ord, ie.offset),
                Some(ckey),
            )?;
        }
    }
    Ok(())
}

fn import_loose(conn: &Connection, source_id: i64, bytes: &[u8], hash: &str) -> rusqlite::Result<()> {
    let ckey = ckey_loose(hash);
    match parse_loose(bytes, LOOSE_HARD_LIMIT) {
        Ok(outcome) => {
            let oid_hex = hex::encode(outcome.oid);
            conn.execute(
                "INSERT INTO candidates(ckey, source_id, source_kind, oid, obj_type, offset, end_offset,
                     declared_size, actual_size, ofs_distance, ref_base, content, has_content, crc_ok, parse_error)
                 VALUES(?1,?2,'loose',?3,?4,NULL,NULL,?5,?6,NULL,NULL,?7,1,NULL,NULL)",
                params![
                    ckey,
                    source_id,
                    oid_hex,
                    outcome.obj_type.type_name(),
                    outcome.declared_size as i64,
                    outcome.data.len() as i64,
                    outcome.data,
                ],
            )?;
        }
        Err(err) => {
            let (msg, code) = match &err {
                crate::loose::LooseError::Truncated => ("zlib 流提前结束".to_string(), "loose_inflate"),
                crate::loose::LooseError::Corrupt(m) => (format!("loose 解析失败: {}", m), "loose_format"),
                crate::loose::LooseError::SizeSpoof { declared, actual } => (
                    format!("大小欺骗：loose 头声明 {} 字节，实际负载 {} 字节", declared, actual),
                    "size_spoof",
                ),
                crate::loose::LooseError::TooLarge(limit) => (
                    format!("解压超出安全硬上限 {} 字节", limit),
                    "too_large",
                ),
            };
            add_issue(conn, Some(source_id), "loose", "error", code, &msg, Some(ckey.clone()))?;
            conn.execute(
                "INSERT INTO candidates(ckey, source_id, source_kind, oid, obj_type, offset, end_offset,
                     declared_size, actual_size, ofs_distance, ref_base, content, has_content, crc_ok, parse_error)
                 VALUES(?1,?2,'loose',NULL,'unknown',NULL,NULL,0,0,NULL,NULL,NULL,0,NULL,?3)",
                params![ckey, source_id, msg],
            )?;
        }
    }
    Ok(())
}

pub fn seed_affected(conn: &Connection, source_id: i64) -> rusqlite::Result<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT ckey FROM candidates WHERE source_id=? ORDER BY ckey",
    )?;
    let rows = stmt.query_map(params![source_id], |r| r.get::<_, String>(0))?;
    rows.collect()
}

#[derive(Serialize)]
pub struct DeletePreview {
    pub source_id: i64,
    pub filename: String,
    pub kind: String,
    pub owned: Vec<String>,
    pub dependents: Vec<DependentInfo>,
}

#[derive(Serialize)]
pub struct DependentInfo {
    pub ckey: String,
    pub oid: Option<String>,
    pub obj_type: String,
    pub source_id: i64,
    pub status: String,
}

pub fn delete_preview(conn: &Connection, source_id: i64) -> rusqlite::Result<Option<DeletePreview>> {
    let info = conn
        .query_row(
            "SELECT filename, kind FROM sources WHERE id=?",
            params![source_id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )
        .optional()?;
    let (filename, kind) = match info {
        Some(v) => v,
        None => return Ok(None),
    };
    let mut stmt = conn.prepare("SELECT ckey FROM candidates WHERE source_id=? ORDER BY ckey")?;
    let owned: Vec<String> = stmt
        .query_map(params![source_id], |r| r.get(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let owned_set: std::collections::HashSet<String> = owned.iter().cloned().collect();
    let mut deps: Vec<DependentInfo> = Vec::new();
    let mut rstmt = conn.prepare(
        "SELECT r.ckey, c.oid, c.obj_type, c.source_id, r.status
         FROM resolved r JOIN candidates c ON c.ckey=r.ckey
         WHERE r.branch_id=(SELECT id FROM branches WHERE name='main')",
    )?;
    let rows = rstmt.query_map([], |r| {
        let chain: String = r.get(0).unwrap_or_default();
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, Option<String>>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, i64>(3)?,
            r.get::<_, String>(4)?,
            chain,
        ))
    })?;
    for row in rows {
        let (ckey, oid, obj_type, sid, status, _chain) = row?;
        if owned_set.contains(&ckey) {
            continue;
        }
        let uses = conn.query_row(
            "SELECT COUNT(*) FROM relink l
             WHERE l.branch_id=(SELECT id FROM branches WHERE name='main')
               AND l.ckey=? AND l.base_ckey IN (SELECT ckey FROM candidates WHERE source_id=?)",
            params![ckey, source_id],
            |r| r.get::<_, i64>(0),
        )? > 0;
        if uses {
            deps.push(DependentInfo {
                ckey,
                oid,
                obj_type,
                source_id: sid,
                status,
            });
        }
    }
    Ok(Some(DeletePreview {
        source_id,
        filename,
        kind,
        owned,
        dependents: deps,
    }))
}

pub fn delete_source(conn: &Connection, source_id: i64, remove_file: bool, data_dir: &std::path::Path) -> rusqlite::Result<bool> {
    let path: Option<String> = conn
        .query_row("SELECT stored_path FROM sources WHERE id=?", params![source_id], |r| r.get(0))
        .optional()?;
    let exists = path.is_some();
    conn.execute("DELETE FROM sources WHERE id=?", params![source_id])?;
    if remove_file {
        if let Some(rel) = path {
            let p = std::path::Path::new(&rel);
            let full = if p.is_absolute() {
                p.to_path_buf()
            } else {
                data_dir.join(p)
            };
            std::fs::remove_file(full).ok();
        }
    }
    Ok(exists)
}

#[derive(Serialize)]
pub struct IssueRow {
    pub id: i64,
    pub source_id: Option<i64>,
    pub scope: String,
    pub severity: String,
    pub code: String,
    pub message: String,
    pub detail: Option<String>,
    pub created_at: i64,
}

pub fn list_issues(conn: &Connection) -> rusqlite::Result<Vec<IssueRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, source_id, scope, severity, code, message, detail, created_at
         FROM issues ORDER BY id",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(IssueRow {
            id: r.get(0)?,
            source_id: r.get(1)?,
            scope: r.get(2)?,
            severity: r.get(3)?,
            code: r.get(4)?,
            message: r.get(5)?,
            detail: r.get(6)?,
            created_at: r.get(7)?,
        })
    })?;
    rows.collect()
}

pub fn pack_parse_json(conn: &Connection, source_id: i64) -> rusqlite::Result<Option<String>> {
    conn.query_row(
        "SELECT parse_json FROM packs WHERE source_id=?",
        params![source_id],
        |r| r.get(0),
    )
    .optional()
}

pub fn idx_fanout(conn: &Connection, source_id: i64) -> rusqlite::Result<Option<(String, Option<i64>)>> {
    conn.query_row(
        "SELECT fanout_json, pack_id FROM idxs WHERE source_id=?",
        params![source_id],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<i64>>(1)?)),
    )
    .optional()
}

pub fn branch_id(conn: &Connection, name: &str) -> rusqlite::Result<i64> {
    conn.query_row("SELECT id FROM branches WHERE name=?", params![name], |r| r.get(0))
}

pub fn create_branch(conn: &Connection, name: &str) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT OR IGNORE INTO branches(name, created_at) VALUES(?, ?)",
        params![name, now_ms()],
    )?;
    let id = branch_id(conn, name)?;
    conn.execute(
        "INSERT OR IGNORE INTO budgets(branch_id, max_depth, total_bytes, single_ratio, used_bytes)
         VALUES(?, ?, ?, ?, 0)",
        params![id, DEFAULT_MAX_DEPTH, DEFAULT_TOTAL_BYTES, DEFAULT_SINGLE_RATIO],
    )?;
    Ok(id)
}

pub fn list_branches(conn: &Connection) -> rusqlite::Result<Vec<(i64, String)>> {
    let mut stmt = conn.prepare("SELECT id, name FROM branches ORDER BY id")?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?;
    rows.collect()
}

#[derive(Serialize, Clone)]
pub struct Budget {
    pub max_depth: i64,
    pub total_bytes: i64,
    pub single_ratio: f64,
    pub used_bytes: i64,
}

pub fn get_budget(conn: &Connection, branch_id: i64) -> rusqlite::Result<Budget> {
    conn.query_row(
        "SELECT max_depth, total_bytes, single_ratio, used_bytes FROM budgets WHERE branch_id=?",
        params![branch_id],
        |r| {
            Ok(Budget {
                max_depth: r.get(0)?,
                total_bytes: r.get(1)?,
                single_ratio: r.get(2)?,
                used_bytes: r.get(3)?,
            })
        },
    )
}

pub fn set_budget(conn: &Connection, branch_id: i64, b: &Budget) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE budgets SET max_depth=?1, total_bytes=?2, single_ratio=?3 WHERE branch_id=?4",
        params![b.max_depth, b.total_bytes, b.single_ratio, branch_id],
    )?;
    Ok(())
}

pub fn reset_used_bytes(conn: &Connection, branch_id: i64) -> rusqlite::Result<()> {
    conn.execute("UPDATE budgets SET used_bytes=0 WHERE branch_id=?", params![branch_id])?;
    Ok(())
}
