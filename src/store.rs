use crate::idx;
use crate::oid;
use crate::pack;
use crate::zutil;
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct SourceRow {
    pub id: i64,
    pub name: String,
    pub digest: String,
    pub size: i64,
    pub kind: String,
    pub stored_path: String,
}

#[derive(Clone, Debug)]
pub struct PackRow {
    pub id: i64,
    pub source_id: i64,
    pub version: i64,
    pub count: i64,
    pub trailer_ok: bool,
    pub parse_error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct EntryRow {
    pub id: i64,
    pub pack_id: i64,
    pub idx: i64,
    pub offset: i64,
    pub kind: String,
    pub declared_size: i64,
    pub data_start: i64,
    pub data_len: i64,
    pub end_offset: i64,
    pub ofs_dist: Option<i64>,
    pub base_offset: Option<i64>,
    pub base_oid: Option<String>,
    pub size_ok: bool,
    pub crc32: i64,
    pub source_id: i64,
}

#[derive(Clone, Debug)]
pub struct LooseRow {
    pub id: i64,
    pub source_id: i64,
    pub kind: String,
    pub size: i64,
    pub parse_error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct CandidateRow {
    pub id: i64,
    pub unit_kind: String,
    pub unit_id: i64,
    pub oid: Option<String>,
    pub kind: Option<String>,
    pub content: Option<Vec<u8>>,
    pub status: String,
    pub error: Option<String>,
    pub depth: i64,
    pub expanded: i64,
    pub generation: i64,
}

#[derive(Clone, Debug)]
pub struct StepRow {
    pub id: i64,
    pub candidate_id: i64,
    pub step_no: i64,
    pub base_kind: String,
    pub base_desc: String,
    pub base_candidate_id: Option<i64>,
    pub instr_json: String,
    pub input_len: i64,
    pub output_len: i64,
    pub verified: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ErrorRow {
    pub id: i64,
    pub scope: String,
    pub ref_id: i64,
    pub kind: String,
    pub message: String,
    pub evidence: String,
}

pub struct Store {
    pub conn: Connection,
    pub data_dir: PathBuf,
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS sources(
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  digest TEXT NOT NULL,
  size INTEGER NOT NULL,
  kind TEXT NOT NULL,
  stored_path TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS packs(
  id INTEGER PRIMARY KEY,
  source_id INTEGER NOT NULL UNIQUE,
  version INTEGER NOT NULL,
  count INTEGER NOT NULL,
  trailer_ok INTEGER NOT NULL,
  parse_error TEXT
);
CREATE TABLE IF NOT EXISTS pack_entries(
  id INTEGER PRIMARY KEY,
  pack_id INTEGER NOT NULL,
  idx INTEGER NOT NULL,
  offset INTEGER NOT NULL,
  kind TEXT NOT NULL,
  declared_size INTEGER NOT NULL,
  header_len INTEGER NOT NULL,
  data_start INTEGER NOT NULL,
  data_len INTEGER NOT NULL,
  end_offset INTEGER NOT NULL,
  ofs_dist INTEGER,
  base_offset INTEGER,
  base_oid TEXT,
  size_ok INTEGER NOT NULL,
  crc32 INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS indexes_meta(
  id INTEGER PRIMARY KEY,
  source_id INTEGER NOT NULL UNIQUE,
  version INTEGER NOT NULL,
  count INTEGER NOT NULL,
  fanout TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS index_entries(
  id INTEGER PRIMARY KEY,
  index_id INTEGER NOT NULL,
  oid TEXT NOT NULL,
  crc32 INTEGER NOT NULL,
  offset INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS loose_objects(
  id INTEGER PRIMARY KEY,
  source_id INTEGER NOT NULL UNIQUE,
  kind TEXT NOT NULL,
  size INTEGER NOT NULL,
  parse_error TEXT
);
CREATE TABLE IF NOT EXISTS candidates(
  id INTEGER PRIMARY KEY,
  unit_kind TEXT NOT NULL,
  unit_id INTEGER NOT NULL,
  oid TEXT,
  kind TEXT,
  content BLOB,
  status TEXT NOT NULL,
  error TEXT,
  depth INTEGER NOT NULL DEFAULT 0,
  expanded INTEGER NOT NULL DEFAULT 0,
  generation INTEGER NOT NULL DEFAULT 0,
  UNIQUE(unit_kind, unit_id)
);
CREATE TABLE IF NOT EXISTS delta_steps(
  id INTEGER PRIMARY KEY,
  candidate_id INTEGER NOT NULL,
  step_no INTEGER NOT NULL,
  base_kind TEXT NOT NULL,
  base_desc TEXT NOT NULL,
  base_candidate_id INTEGER,
  instr_json TEXT NOT NULL,
  input_len INTEGER NOT NULL,
  output_len INTEGER NOT NULL,
  verified INTEGER NOT NULL,
  error TEXT
);
CREATE TABLE IF NOT EXISTS blocks(
  id INTEGER PRIMARY KEY,
  candidate_id INTEGER NOT NULL,
  blocked_by TEXT NOT NULL,
  reason TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS errors_log(
  id INTEGER PRIMARY KEY,
  scope TEXT NOT NULL,
  ref_id INTEGER NOT NULL,
  kind TEXT NOT NULL,
  message TEXT NOT NULL,
  evidence TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS branches(
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  oid TEXT NOT NULL,
  candidate_id INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS engine_state(
  id INTEGER PRIMARY KEY CHECK(id = 1),
  status TEXT NOT NULL,
  message TEXT NOT NULL,
  expanded_bytes INTEGER NOT NULL DEFAULT 0,
  run_count INTEGER NOT NULL DEFAULT 0
);
"#;

impl Store {
    pub fn open(data_dir: &Path) -> Result<Store, String> {
        std::fs::create_dir_all(data_dir).map_err(|e| format!("create data dir: {e}"))?;
        let files_dir = data_dir.join("files");
        std::fs::create_dir_all(&files_dir).map_err(|e| format!("create files dir: {e}"))?;
        let db_path = data_dir.join("microscope.db");
        let conn = Connection::open(&db_path).map_err(|e| format!("open sqlite: {e}"))?;
        conn.execute_batch(SCHEMA)
            .map_err(|e| format!("migrate: {e}"))?;
        conn.execute(
            "INSERT OR IGNORE INTO engine_state(id,status,message) VALUES(1,'idle','')",
            [],
        )
        .map_err(|e| e.to_string())?;
        Ok(Store {
            conn,
            data_dir: data_dir.to_path_buf(),
        })
    }

    /// 导入文件: 计算 SHA-256 内容摘要, 复制进数据目录, 按类型解析。
    /// 返回 (source_id, kind)。
    pub fn add_source(&self, name: &str, bytes: &[u8]) -> Result<(i64, String), String> {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let digest = hex::encode(hasher.finalize());

        let kind = detect_kind(bytes);
        let safe_name: String = name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let stored_rel = format!("files/{}_{}", &digest[..16], safe_name);
        std::fs::write(self.data_dir.join(&stored_rel), bytes)
            .map_err(|e| format!("write source file: {e}"))?;

        self.conn
            .execute(
                "INSERT INTO sources(name, digest, size, kind, stored_path)
                 VALUES (?1,?2,?3,?4,?5)",
                params![safe_name, digest, bytes.len() as i64, kind, stored_rel],
            )
            .map_err(|e| e.to_string())?;
        let source_id = self.conn.last_insert_rowid();

        match kind {
            "pack" => self.ingest_pack(source_id, bytes)?,
            "index" => self.ingest_index(source_id, bytes)?,
            "loose" => self.ingest_loose(source_id, bytes)?,
            _ => self.add_error(
                "source",
                source_id,
                "unrecognized_format",
                "not a PACK file, idx v2 file, or zlib loose object",
                "",
            ),
        }
        Ok((source_id, kind.to_string()))
    }

    fn ingest_pack(&self, source_id: i64, bytes: &[u8]) -> Result<(), String> {
        let parsed = pack::parse_pack(bytes)?;
        self.conn
            .execute(
                "INSERT INTO packs(source_id, version, count, trailer_ok, parse_error)
                 VALUES (?1,?2,?3,?4,?5)",
                params![
                    source_id,
                    parsed.version as i64,
                    parsed.count as i64,
                    parsed.trailer_ok as i64,
                    parsed.parse_error
                ],
            )
            .map_err(|e| e.to_string())?;
        let pack_id = self.conn.last_insert_rowid();
        for e in &parsed.entries {
            self.conn
                .execute(
                    "INSERT INTO pack_entries(pack_id, idx, offset, kind, declared_size,
                       header_len, data_start, data_len, end_offset, ofs_dist, base_offset,
                       base_oid, size_ok, crc32)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
                    params![
                        pack_id,
                        e.index as i64,
                        e.offset as i64,
                        e.kind.as_str(),
                        e.declared_size as i64,
                        e.header_len as i64,
                        e.data_start as i64,
                        e.data_len as i64,
                        e.end_offset as i64,
                        e.ofs_dist.map(|v| v as i64),
                        e.base_offset.map(|v| v as i64),
                        e.base_oid.map(|o| oid::to_hex(&o)),
                        e.size_ok as i64,
                        e.crc32 as i64
                    ],
                )
                .map_err(|e| e.to_string())?;
        }
        if !parsed.trailer_ok {
            self.add_error(
                "pack",
                pack_id,
                "trailer_mismatch",
                "pack trailer SHA1 does not match file contents",
                "",
            );
        }
        if let Some(msg) = &parsed.parse_error {
            self.add_error("pack", pack_id, "parse_error", msg, "");
        }
        Ok(())
    }

    fn ingest_index(&self, source_id: i64, bytes: &[u8]) -> Result<(), String> {
        let parsed = idx::parse_index(bytes)?;
        let fanout_json = serde_json::to_string(&parsed.fanout.to_vec()).unwrap();
        self.conn
            .execute(
                "INSERT INTO indexes_meta(source_id, version, count, fanout)
                 VALUES (?1,?2,?3,?4)",
                params![
                    source_id,
                    parsed.version as i64,
                    parsed.entries.len() as i64,
                    fanout_json
                ],
            )
            .map_err(|e| e.to_string())?;
        let index_id = self.conn.last_insert_rowid();
        for e in &parsed.entries {
            self.conn
                .execute(
                    "INSERT INTO index_entries(index_id, oid, crc32, offset)
                     VALUES (?1,?2,?3,?4)",
                    params![index_id, oid::to_hex(&e.oid), e.crc32 as i64, e.offset as i64],
                )
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    fn ingest_loose(&self, source_id: i64, bytes: &[u8]) -> Result<(), String> {
        match parse_loose(bytes) {
            Ok((kind, content)) => {
                self.conn
                    .execute(
                        "INSERT INTO loose_objects(source_id, kind, size, parse_error)
                         VALUES (?1,?2,?3,NULL)",
                        params![source_id, kind, content.len() as i64],
                    )
                    .map_err(|e| e.to_string())?;
            }
            Err(msg) => {
                self.conn
                    .execute(
                        "INSERT INTO loose_objects(source_id, kind, size, parse_error)
                         VALUES (?1,'unknown',0,?2)",
                        params![source_id, msg],
                    )
                    .map_err(|e| e.to_string())?;
                let loose_id = self.conn.last_insert_rowid();
                self.add_error("loose", loose_id, "parse_error", &msg, "");
            }
        }
        Ok(())
    }

    pub fn source_bytes(&self, source_id: i64) -> Result<Vec<u8>, String> {
        let rel: String = self
            .conn
            .query_row(
                "SELECT stored_path FROM sources WHERE id=?1",
                params![source_id],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        std::fs::read(self.data_dir.join(rel)).map_err(|e| e.to_string())
    }

    pub fn list_sources(&self) -> Vec<SourceRow> {
        let mut stmt = self
            .conn
            .prepare("SELECT id,name,digest,size,kind,stored_path FROM sources ORDER BY digest")
            .unwrap();
        stmt.query_map([], |r| {
            Ok(SourceRow {
                id: r.get(0)?,
                name: r.get(1)?,
                digest: r.get(2)?,
                size: r.get(3)?,
                kind: r.get(4)?,
                stored_path: r.get(5)?,
            })
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }

    pub fn add_error(&self, scope: &str, ref_id: i64, kind: &str, message: &str, evidence: &str) {
        let _ = self.conn.execute(
            "INSERT INTO errors_log(scope, ref_id, kind, message, evidence)
             VALUES (?1,?2,?3,?4,?5)",
            params![scope, ref_id, kind, message, evidence],
        );
    }

    pub fn clear_errors_scope(&self, scope: &str) {
        let _ = self
            .conn
            .execute("DELETE FROM errors_log WHERE scope=?1", params![scope]);
    }

    pub fn errors(&self) -> Vec<ErrorRow> {
        let mut stmt = self
            .conn
            .prepare("SELECT id,scope,ref_id,kind,message,evidence FROM errors_log ORDER BY id")
            .unwrap();
        stmt.query_map([], |r| {
            Ok(ErrorRow {
                id: r.get(0)?,
                scope: r.get(1)?,
                ref_id: r.get(2)?,
                kind: r.get(3)?,
                message: r.get(4)?,
                evidence: r.get(5)?,
            })
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }
}

pub fn detect_kind(bytes: &[u8]) -> &'static str {
    if bytes.len() >= 4 && &bytes[0..4] == b"PACK" {
        "pack"
    } else if bytes.len() >= 4 && &bytes[0..4] == b"\xfftOc" {
        "index"
    } else if parse_loose(bytes).is_ok() {
        "loose"
    } else {
        "unknown"
    }
}

/// loose object: zlib("{type} {size}\0{content}")
pub fn parse_loose(bytes: &[u8]) -> Result<(String, Vec<u8>), String> {
    let inf = zutil::inflate_bounded(bytes)?;
    let nul = inf
        .data
        .iter()
        .position(|b| *b == 0)
        .ok_or("loose object header missing NUL")?;
    let header = std::str::from_utf8(&inf.data[..nul]).map_err(|_| "loose header not utf8")?;
    let mut parts = header.splitn(2, ' ');
    let kind = parts.next().ok_or("loose header missing type")?;
    let size: usize = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or("loose header missing size")?;
    if !matches!(kind, "blob" | "tree" | "commit" | "tag") {
        return Err(format!("loose header bad type {kind}"));
    }
    let content = inf.data[nul + 1..].to_vec();
    if content.len() != size {
        return Err(format!(
            "loose size spoof: header says {size}, content is {}",
            content.len()
        ));
    }
    Ok((kind.to_string(), content))
}

const ENTRY_SELECT: &str =
    "SELECT e.id, e.pack_id, e.idx, e.offset, e.kind, e.declared_size,
            e.data_start, e.data_len, e.end_offset, e.ofs_dist, e.base_offset,
            e.base_oid, e.size_ok, e.crc32, p.source_id
     FROM pack_entries e JOIN packs p ON p.id = e.pack_id";

fn map_entry(r: &rusqlite::Row) -> rusqlite::Result<EntryRow> {
    Ok(EntryRow {
        id: r.get(0)?,
        pack_id: r.get(1)?,
        idx: r.get(2)?,
        offset: r.get(3)?,
        kind: r.get(4)?,
        declared_size: r.get(5)?,
        data_start: r.get(6)?,
        data_len: r.get(7)?,
        end_offset: r.get(8)?,
        ofs_dist: r.get(9)?,
        base_offset: r.get(10)?,
        base_oid: r.get(11)?,
        size_ok: r.get::<_, i64>(12)? != 0,
        crc32: r.get(13)?,
        source_id: r.get(14)?,
    })
}

fn map_candidate(r: &rusqlite::Row) -> rusqlite::Result<CandidateRow> {
    Ok(CandidateRow {
        id: r.get(0)?,
        unit_kind: r.get(1)?,
        unit_id: r.get(2)?,
        oid: r.get(3)?,
        kind: r.get(4)?,
        content: r.get(5)?,
        status: r.get(6)?,
        error: r.get(7)?,
        depth: r.get(8)?,
        expanded: r.get(9)?,
        generation: r.get(10)?,
    })
}

impl Store {
    pub fn packs(&self) -> Vec<PackRow> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, source_id, version, count, trailer_ok, parse_error
                 FROM packs ORDER BY id",
            )
            .unwrap();
        stmt.query_map([], |r| {
            Ok(PackRow {
                id: r.get(0)?,
                source_id: r.get(1)?,
                version: r.get(2)?,
                count: r.get(3)?,
                trailer_ok: r.get::<_, i64>(4)? != 0,
                parse_error: r.get(5)?,
            })
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }

    pub fn pack_entries(&self, pack_id: i64) -> Vec<EntryRow> {
        let sql = format!("{ENTRY_SELECT} WHERE e.pack_id=?1 ORDER BY e.idx");
        let mut stmt = self.conn.prepare(&sql).unwrap();
        stmt.query_map(params![pack_id], map_entry)
            .unwrap()
            .filter_map(|r| r.ok())
            .collect()
    }

    pub fn all_entries(&self) -> Vec<EntryRow> {
        let sql = format!("{ENTRY_SELECT} ORDER BY p.source_id, e.idx");
        let mut stmt = self.conn.prepare(&sql).unwrap();
        stmt.query_map([], map_entry)
            .unwrap()
            .filter_map(|r| r.ok())
            .collect()
    }

    /// 所有 pack 中位于给定原始偏移的 entry, 按来源摘要排序 (与导入顺序无关)。
    pub fn entries_at_offset(&self, offset: i64) -> Vec<EntryRow> {
        let sql = format!(
            "{ENTRY_SELECT} WHERE e.offset=?1
             ORDER BY (SELECT digest FROM sources WHERE id=p.source_id), p.id"
        );
        let mut stmt = self.conn.prepare(&sql).unwrap();
        stmt.query_map(params![offset], map_entry)
            .unwrap()
            .filter_map(|r| r.ok())
            .collect()
    }

    pub fn entry_by_id(&self, id: i64) -> Option<EntryRow> {
        let sql = format!("{ENTRY_SELECT} WHERE e.id=?1");
        self.conn
            .query_row(&sql, params![id], map_entry)
            .ok()
    }

    pub fn entry_in_pack_at_offset(&self, pack_id: i64, offset: i64) -> Option<EntryRow> {
        let sql = format!("{ENTRY_SELECT} WHERE e.pack_id=?1 AND e.offset=?2");
        self.conn
            .query_row(&sql, params![pack_id, offset], map_entry)
            .ok()
    }

    pub fn all_loose(&self) -> Vec<LooseRow> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, source_id, kind, size, parse_error
                 FROM loose_objects ORDER BY source_id",
            )
            .unwrap();
        stmt.query_map([], |r| {
            Ok(LooseRow {
                id: r.get(0)?,
                source_id: r.get(1)?,
                kind: r.get(2)?,
                size: r.get(3)?,
                parse_error: r.get(4)?,
            })
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }

    pub fn loose_by_id(&self, id: i64) -> Option<LooseRow> {
        self.conn
            .query_row(
                "SELECT id, source_id, kind, size, parse_error
                 FROM loose_objects WHERE id=?1",
                params![id],
                |r| {
                    Ok(LooseRow {
                        id: r.get(0)?,
                        source_id: r.get(1)?,
                        kind: r.get(2)?,
                        size: r.get(3)?,
                        parse_error: r.get(4)?,
                    })
                },
            )
            .ok()
    }

    pub fn index_entries_by_oid(&self, oid_hex: &str) -> Vec<(i64, i64, i64)> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT ie.index_id, ie.offset, ie.crc32
                 FROM index_entries ie
                 JOIN indexes_meta im ON im.id = ie.index_id
                 JOIN sources s ON s.id = im.source_id
                 WHERE ie.oid=?1
                 ORDER BY s.digest, ie.id",
            )
            .unwrap();
        stmt.query_map(params![oid_hex], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }

    pub fn index_entries_at_offset(&self, offset: i64) -> Vec<(String, i64, i64)> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT ie.oid, ie.crc32, ie.index_id FROM index_entries ie
                 WHERE ie.offset=?1 ORDER BY ie.id",
            )
            .unwrap();
        stmt.query_map(params![offset], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }

    pub fn all_index_entries(&self) -> Vec<(i64, String, i64, i64)> {
        let mut stmt = self
            .conn
            .prepare("SELECT index_id, oid, crc32, offset FROM index_entries ORDER BY id")
            .unwrap();
        stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
            ))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }

    pub fn ensure_candidate(&self, unit_kind: &str, unit_id: i64) {
        let _ = self.conn.execute(
            "INSERT OR IGNORE INTO candidates(unit_kind, unit_id, status)
             VALUES (?1,?2,'pending')",
            params![unit_kind, unit_id],
        );
    }

    const CANDIDATE_SELECT: &'static str =
        "SELECT id, unit_kind, unit_id, oid, kind, content, status, error,
                depth, expanded, generation FROM candidates";

    pub fn candidate(&self, unit_kind: &str, unit_id: i64) -> Option<CandidateRow> {
        let sql = format!(
            "{} WHERE unit_kind=?1 AND unit_id=?2",
            Self::CANDIDATE_SELECT
        );
        self.conn
            .query_row(&sql, params![unit_kind, unit_id], map_candidate)
            .ok()
    }

    pub fn candidate_by_id(&self, id: i64) -> Option<CandidateRow> {
        let sql = format!("{} WHERE id=?1", Self::CANDIDATE_SELECT);
        self.conn.query_row(&sql, params![id], map_candidate).ok()
    }

    pub fn all_candidates(&self) -> Vec<CandidateRow> {
        let sql = format!("{} ORDER BY id", Self::CANDIDATE_SELECT);
        let mut stmt = self.conn.prepare(&sql).unwrap();
        stmt.query_map([], map_candidate)
            .unwrap()
            .filter_map(|r| r.ok())
            .collect()
    }

    /// 待处理候选: pending / blocked / paused, 按稳定 id 顺序。
    pub fn actionable_candidates(&self) -> Vec<CandidateRow> {
        let sql = format!(
            "{} WHERE status IN ('pending','blocked','paused') ORDER BY id",
            Self::CANDIDATE_SELECT
        );
        let mut stmt = self.conn.prepare(&sql).unwrap();
        stmt.query_map([], map_candidate)
            .unwrap()
            .filter_map(|r| r.ok())
            .collect()
    }

    /// 同一 oid 的全部成功候选, 按来源摘要+偏移排序, 与导入顺序无关。
    pub fn ok_candidates_by_oid(&self, oid_hex: &str) -> Vec<CandidateRow> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT c.id, c.unit_kind, c.unit_id, c.oid, c.kind, c.content, c.status,
                        c.error, c.depth, c.expanded, c.generation
                 FROM candidates c
                 LEFT JOIN pack_entries e ON c.unit_kind='entry' AND c.unit_id=e.id
                 LEFT JOIN packs p ON e.pack_id=p.id
                 LEFT JOIN loose_objects l ON c.unit_kind='loose' AND c.unit_id=l.id
                 LEFT JOIN sources s ON s.id=COALESCE(p.source_id, l.source_id)
                 WHERE c.oid=?1 AND c.status='ok'
                 ORDER BY s.digest, e.offset, l.id, c.id",
            )
            .unwrap();
        stmt.query_map(params![oid_hex], map_candidate)
            .unwrap()
            .filter_map(|r| r.ok())
            .collect()
    }

    pub fn candidates_by_oid(&self, oid_hex: &str) -> Vec<CandidateRow> {
        let sql = format!(
            "{} WHERE oid=?1 ORDER BY id",
            Self::CANDIDATE_SELECT
        );
        let mut stmt = self.conn.prepare(&sql).unwrap();
        stmt.query_map(params![oid_hex], map_candidate)
            .unwrap()
            .filter_map(|r| r.ok())
            .collect()
    }

    pub fn set_candidate_ok(
        &self,
        unit_kind: &str,
        unit_id: i64,
        oid_hex: &str,
        kind: &str,
        content: &[u8],
        depth: i64,
        expanded: i64,
    ) -> i64 {
        self.conn
            .execute(
                "INSERT INTO candidates(unit_kind, unit_id, oid, kind, content, status, error,
                     depth, expanded, generation)
                 VALUES (?1,?2,?3,?4,?5,'ok',NULL,?6,?7,1)
                 ON CONFLICT(unit_kind, unit_id) DO UPDATE SET
                   oid=excluded.oid, kind=excluded.kind, content=excluded.content,
                   status='ok', error=NULL, depth=excluded.depth,
                   expanded=excluded.expanded, generation=candidates.generation+1",
                params![
                    unit_kind,
                    unit_id,
                    oid_hex,
                    kind,
                    content,
                    depth,
                    expanded
                ],
            )
            .unwrap();
        self.conn
            .query_row(
                "SELECT id FROM candidates WHERE unit_kind=?1 AND unit_id=?2",
                params![unit_kind, unit_id],
                |r| r.get(0),
            )
            .unwrap()
    }

    pub fn set_candidate_status(
        &self,
        unit_kind: &str,
        unit_id: i64,
        status: &str,
        error: Option<&str>,
    ) {
        self.conn
            .execute(
                "INSERT INTO candidates(unit_kind, unit_id, status, error, generation)
                 VALUES (?1,?2,?3,?4,1)
                 ON CONFLICT(unit_kind, unit_id) DO UPDATE SET
                   status=excluded.status, error=excluded.error,
                   oid=CASE WHEN excluded.status='ok' THEN candidates.oid ELSE NULL END,
                   kind=CASE WHEN excluded.status='ok' THEN candidates.kind ELSE NULL END,
                   content=CASE WHEN excluded.status='ok' THEN candidates.content ELSE NULL END,
                   generation=candidates.generation+1",
                params![unit_kind, unit_id, status, error],
            )
            .unwrap();
    }

    pub fn replace_steps(&self, candidate_id: i64, steps: &[StepForStore]) {
        self.conn
            .execute(
                "DELETE FROM delta_steps WHERE candidate_id=?1",
                params![candidate_id],
            )
            .unwrap();
        for (i, s) in steps.iter().enumerate() {
            self.conn
                .execute(
                    "INSERT INTO delta_steps(candidate_id, step_no, base_kind, base_desc,
                         base_candidate_id, instr_json, input_len, output_len, verified, error)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                    params![
                        candidate_id,
                        i as i64,
                        s.base_kind,
                        s.base_desc,
                        s.base_candidate_id,
                        s.instr_json,
                        s.input_len,
                        s.output_len,
                        s.verified as i64,
                        s.error
                    ],
                )
                .unwrap();
        }
    }

    pub fn clear_steps_for(&self, candidate_id: i64) {
        self.conn
            .execute(
                "DELETE FROM delta_steps WHERE candidate_id=?1",
                params![candidate_id],
            )
            .unwrap();
    }

    pub fn steps_of(&self, candidate_id: i64) -> Vec<StepRow> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id,candidate_id,step_no,base_kind,base_desc,base_candidate_id,
                        instr_json,input_len,output_len,verified,error
                 FROM delta_steps WHERE candidate_id=?1 ORDER BY step_no",
            )
            .unwrap();
        stmt.query_map(params![candidate_id], |r| {
            Ok(StepRow {
                id: r.get(0)?,
                candidate_id: r.get(1)?,
                step_no: r.get(2)?,
                base_kind: r.get(3)?,
                base_desc: r.get(4)?,
                base_candidate_id: r.get(5)?,
                instr_json: r.get(6)?,
                input_len: r.get(7)?,
                output_len: r.get(8)?,
                verified: r.get::<_, i64>(9)? != 0,
                error: r.get(10)?,
            })
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }

    pub fn all_steps(&self) -> Vec<StepRow> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id,candidate_id,step_no,base_kind,base_desc,base_candidate_id,
                        instr_json,input_len,output_len,verified,error
                 FROM delta_steps ORDER BY id",
            )
            .unwrap();
        stmt.query_map([], |r| {
            Ok(StepRow {
                id: r.get(0)?,
                candidate_id: r.get(1)?,
                step_no: r.get(2)?,
                base_kind: r.get(3)?,
                base_desc: r.get(4)?,
                base_candidate_id: r.get(5)?,
                instr_json: r.get(6)?,
                input_len: r.get(7)?,
                output_len: r.get(8)?,
                verified: r.get::<_, i64>(9)? != 0,
                error: r.get(10)?,
            })
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }

    pub fn replace_blocks(&self, candidate_id: i64, blocks: &[(String, String)]) {
        self.conn
            .execute(
                "DELETE FROM blocks WHERE candidate_id=?1",
                params![candidate_id],
            )
            .unwrap();
        for (blocked_by, reason) in blocks {
            self.conn
                .execute(
                    "INSERT INTO blocks(candidate_id, blocked_by, reason)
                     VALUES (?1,?2,?3)",
                    params![candidate_id, blocked_by, reason],
                )
                .unwrap();
        }
    }

    pub fn all_blocks(&self) -> Vec<(i64, String, String)> {
        let mut stmt = self
            .conn
            .prepare("SELECT candidate_id, blocked_by, reason FROM blocks ORDER BY id")
            .unwrap();
        stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }

    pub fn set_engine_state(&self, status: &str, message: &str, expanded: i64) {
        self.conn
            .execute(
                "UPDATE engine_state SET status=?1, message=?2, expanded_bytes=?3,
                    run_count=run_count+1 WHERE id=1",
                params![status, message, expanded],
            )
            .unwrap();
    }

    pub fn engine_state(&self) -> (String, String, i64, i64) {
        self.conn
            .query_row(
                "SELECT status, message, expanded_bytes, run_count FROM engine_state WHERE id=1",
                [],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, i64>(3)?,
                    ))
                },
            )
            .unwrap()
    }

    pub fn add_branch(&self, name: &str, oid_hex: &str, candidate_id: i64) -> Result<(), String> {
        let ok = self
            .conn
            .query_row(
                "SELECT oid FROM candidates WHERE id=?1 AND status='ok'",
                params![candidate_id],
                |r| r.get::<_, String>(0),
            )
            .map_err(|_| "candidate not found or not resolved".to_string())?;
        if ok != oid_hex {
            return Err("pinned candidate oid does not match".to_string());
        }
        self.conn
            .execute(
                "INSERT INTO branches(name, oid, candidate_id) VALUES (?1,?2,?3)",
                params![name, oid_hex, candidate_id],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn branches(&self) -> Vec<(i64, String, String, i64)> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, name, oid, candidate_id FROM branches ORDER BY id")
            .unwrap();
        stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
            ))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }
}

#[derive(Clone, Debug, Default)]
pub struct StepForStore {
    pub base_kind: String,
    pub base_desc: String,
    pub base_candidate_id: Option<i64>,
    pub instr_json: String,
    pub input_len: i64,
    pub output_len: i64,
    pub verified: bool,
    pub error: Option<String>,
}

impl Store {
    /// 删除源文件前, 找出仍直接或间接依赖它的对象候选。
    pub fn dependents_of_source(&self, source_id: i64) -> Vec<CandidateRow> {
        let mut roots: std::collections::HashSet<i64> = Default::default();
        for e in self.all_entries() {
            if e.source_id == source_id {
                if let Some(c) = self.candidate("entry", e.id) {
                    roots.insert(c.id);
                }
            }
        }
        for l in self.all_loose() {
            if l.source_id == source_id {
                if let Some(c) = self.candidate("loose", l.id) {
                    roots.insert(c.id);
                }
            }
        }
        // base_candidate_id -> 直接以它为 base 的子候选
        let mut children: std::collections::HashMap<i64, Vec<i64>> = Default::default();
        for step in self.all_steps() {
            if let Some(base_id) = step.base_candidate_id {
                children.entry(base_id).or_default().push(step.candidate_id);
            }
        }
        let mut affected: std::collections::HashSet<i64> = roots.clone();
        let mut stack: Vec<i64> = roots.into_iter().collect();
        while let Some(id) = stack.pop() {
            if let Some(kids) = children.get(&id) {
                for kid in kids {
                    if affected.insert(*kid) {
                        stack.push(*kid);
                    }
                }
            }
        }
        let mut out: Vec<CandidateRow> = affected
            .iter()
            .filter_map(|id| self.candidate_by_id(*id))
            .collect();
        out.sort_by_key(|c| c.id);
        out
    }

    /// 删除源文件及其全部单元; 返回受影响的外部候选 id (依赖链断裂者)。
    pub fn delete_source(&self, source_id: i64) -> Vec<i64> {
        let affected = self.dependents_of_source(source_id);
        let own: std::collections::HashSet<i64> = affected
            .iter()
            .filter(|c| unit_source_id(self, c) == Some(source_id))
            .map(|c| c.id)
            .collect();
        let external: Vec<i64> = affected
            .iter()
            .map(|c| c.id)
            .filter(|id| !own.contains(id))
            .collect();

        for id in &own {
            self.conn
                .execute("DELETE FROM delta_steps WHERE candidate_id=?1", params![id])
                .unwrap();
            self.conn
                .execute("DELETE FROM blocks WHERE candidate_id=?1", params![id])
                .unwrap();
            self.conn
                .execute("DELETE FROM errors_log WHERE scope='candidate' AND ref_id=?1", params![id])
                .unwrap();
            self.conn
                .execute("DELETE FROM candidates WHERE id=?1", params![id])
                .unwrap();
        }
        self.conn
            .execute(
                "DELETE FROM pack_entries WHERE pack_id IN
                 (SELECT id FROM packs WHERE source_id=?1)",
                params![source_id],
            )
            .unwrap();
        self.conn
            .execute("DELETE FROM packs WHERE source_id=?1", params![source_id])
            .unwrap();
        self.conn
            .execute(
                "DELETE FROM index_entries WHERE index_id IN
                 (SELECT id FROM indexes_meta WHERE source_id=?1)",
                params![source_id],
            )
            .unwrap();
        self.conn
            .execute("DELETE FROM indexes_meta WHERE source_id=?1", params![source_id])
            .unwrap();
        self.conn
            .execute("DELETE FROM loose_objects WHERE source_id=?1", params![source_id])
            .unwrap();
        let path: String = self
            .conn
            .query_row(
                "SELECT stored_path FROM sources WHERE id=?1",
                params![source_id],
                |r| r.get(0),
            )
            .unwrap_or_default();
        let _ = std::fs::remove_file(self.data_dir.join(path));
        self.conn
            .execute("DELETE FROM sources WHERE id=?1", params![source_id])
            .unwrap();

        // 外部候选的 base 已消失: 清掉旧步骤, 回到 pending 由引擎重算。
        for id in &external {
            self.conn
                .execute("DELETE FROM delta_steps WHERE candidate_id=?1", params![id])
                .unwrap();
            self.conn
                .execute("DELETE FROM blocks WHERE candidate_id=?1", params![id])
                .unwrap();
            self.conn
                .execute(
                    "UPDATE candidates SET status='pending', oid=NULL, kind=NULL,
                        content=NULL, error=NULL WHERE id=?1",
                    params![id],
                )
                .unwrap();
        }
        external
    }

    pub fn source_name(&self, source_id: i64) -> String {
        self.conn
            .query_row(
                "SELECT name FROM sources WHERE id=?1",
                params![source_id],
                |r| r.get(0),
            )
            .unwrap_or_default()
    }
}

fn unit_source_id(store: &Store, c: &CandidateRow) -> Option<i64> {
    match c.unit_kind.as_str() {
        "entry" => store.entry_by_id(c.unit_id).map(|e| e.source_id),
        "loose" => store.loose_by_id(c.unit_id).map(|l| l.source_id),
        _ => None,
    }
}
}
