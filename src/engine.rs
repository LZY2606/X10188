use crate::db::DEFAULT_BRANCH;
use crate::delta::{apply_delta, Budget};
use crate::gitenc::{oid_hex, oid_sha1};
use crate::idx::parse_idx;
use crate::loose::parse_loose;
use crate::model::{LooseInfo, ObjKind, PackEntry, SourceKind};
use crate::pack::{pack_sha1, parse_pack};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use sha1::{Digest, Sha1};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize)]
pub struct ImportReport {
    pub file_id: i64,
    pub kind: String,
    pub stored_path: String,
    pub providers_added: i64,
    pub notes: Vec<String>,
}

pub fn sha1_hex(buf: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(buf);
    oid_hex(&h.finalize())
}

fn sniff(buf: &[u8]) -> &'static str {
    if buf.len() >= 4 && &buf[0..4] == b"PACK" {
        "pack"
    } else if buf.len() >= 4 && &buf[0..4] == b"\xfftOc" {
        "idx"
    } else if buf.len() >= 4 && buf[0] == 0x78 {
        // v1 idx begins with a fanout entry; treat 0x78.. as compressed loose.
        "loose"
    } else {
        "unknown"
    }
}

pub struct Engine {
    pub data_dir: PathBuf,
}

impl Engine {
    pub fn new(data_dir: PathBuf) -> Self {
        Engine { data_dir }
    }

    pub fn conn(&self) -> rusqlite::Result<Connection> {
        crate::db::open(&self.data_dir)
    }

    /// Store an imported file under the data directory (never outside it) and
    /// parse it. Returns a report of what was added.
    pub fn import_bytes(&self, conn: &mut Connection, name: &str, buf: &[u8]) -> ImportReport {
        let digest = sha1_hex(buf);
        let ext = Path::new(name)
            .extension()
            .map(|e| e.to_string_lossy().to_string())
            .unwrap_or_default();
        let stored_rel = format!("objects/{}.{}", digest, if ext.is_empty() { "bin" } else { &ext });
        let stored = self.data_dir.join(&stored_rel);
        let mut notes = Vec::new();
        if !stored.exists() {
            std::fs::write(&stored, buf).expect("write data file");
        } else {
            notes.push("identical content already stored (deduplicated)".into());
        }
        let detected = sniff(buf);
        let kind = match ext.as_str() {
            "pack" => "pack",
            "idx" => "idx",
            _ => detected,
        };

        let tx = conn.transaction().unwrap();
        let existing: Option<i64> = tx
            .query_row("SELECT id FROM source_file WHERE object_path=?1", params![stored_rel], |r| {
                r.get(0)
            })
            .optional()
            .unwrap();
        let file_id = if let Some(id) = existing {
            notes.push("source already imported; re-indexing content".into());
            // Replace children but reuse id.
            tx.execute("DELETE FROM object_provider WHERE file_id=?1", params![id]).unwrap();
            tx.execute("DELETE FROM pack_file WHERE file_id=?1", params![id]).unwrap();
            tx.execute("DELETE FROM idx_file WHERE file_id=?1", params![id]).unwrap();
            tx.execute("DELETE FROM loose_object WHERE file_id=?1", params![id]).unwrap();
            tx.execute("UPDATE source_file SET kind=?1, original_name=?2, size=?3, sha1=?4, parse_note=NULL WHERE id=?5",
                params![kind, name, buf.len() as i64, digest, id]).unwrap();
            id
        } else {
            tx.execute(
                "INSERT INTO source_file(object_path, original_name, kind, size, sha1) VALUES(?1,?2,?3,?4,?5)",
                params![stored_rel, name, kind, buf.len() as i64, digest],
            )
            .unwrap() as i64
        };

        let mut providers_added = 0i64;
        match kind {
            "pack" => {
                providers_added = self.ingest_pack(&tx, file_id, buf, &mut notes);
            }
            "idx" => {
                self.ingest_idx(&tx, file_id, buf, &mut notes);
            }
            "loose" => {
                providers_added = self.ingest_loose(&tx, file_id, name, buf, &mut notes);
            }
            other => {
                let msg = format!("unrecognized file type: {}", other);
                notes.push(msg.clone());
                tx.execute("UPDATE source_file SET parse_note=?1 WHERE id=?2", params![msg, file_id]).unwrap();
            }
        }

        tx.execute(
            "UPDATE source_file SET parse_note=?1 WHERE id=?2",
            params![notes.join("; "), file_id],
        )
        .unwrap();
        tx.commit().unwrap();

        // Re-resolve after import, then recompute affected subgraphs if the
        // new file supplies new bases.
        self.resolve(DEFAULT_BRANCH, "import", None, conn);
        self.recompute_after_import(conn, file_id, &notes);

        ImportReport { file_id, kind: kind.to_string(), stored_path: stored_rel, providers_added, notes }
    }

    fn recompute_after_import(&self, conn: &mut Connection, file_id: i64, notes: &mut Vec<String>) {
        // Any provider whose base providers were added by this file.
        let new_providers: Vec<i64> = {
            let mut s = conn.prepare("SELECT id FROM object_provider WHERE file_id=?1").unwrap();
            s.query_map(params![file_id], |r| r.get::<_, i64>(0)).unwrap().flatten().collect()
        };
        if new_providers.is_empty() {
            return;
        }
        let affected = self.forward_dependents(conn, &new_providers);
        if affected.is_empty() {
            return;
        }
        notes.push(format!("base added: recomputing {} dependent object(s)", affected.len()));
        self.resolve(DEFAULT_BRANCH, "base-added", Some(affected), conn);
    }

    fn forward_dependents(&self, conn: &Connection, starts: &[i64]) -> HashSet<i64> {
        let mut result: HashSet<i64> = HashSet::new();
        let mut stack: Vec<i64> = starts.to_vec();
        while let Some(pid) = stack.pop() {
            // dependents whose ofs target is this provider
            let mut q = conn
                .prepare("SELECT id FROM object_provider WHERE is_delta=1 AND ofs_target_offset IN (\
                    SELECT pack_offset FROM object_provider WHERE id=?1) AND file_id=\
                    (SELECT file_id FROM object_provider WHERE id=?1)")
                .unwrap();
            let deps: Vec<i64> = q.query_map(params![pid], |r| r.get(0)).unwrap().flatten().collect();
            drop(q);
            // dependents whose claimed/computed oid equals a target oid of this provider
            let oids: Vec<String> = {
                let mut s = conn.prepare("SELECT claimed_oid, computed_oid FROM object_provider WHERE id=?1").unwrap();
                s.query_row(params![pid], |r| {
                    let a: Option<String> = r.get(0)?;
                    let b: Option<String> = r.get(1)?;
                    Ok([a, b].into_iter().flatten().collect::<Vec<_>>())
                })
                .unwrap_or_default()
            };
            let mut refdeps: Vec<i64> = Vec::new();
            for oid in oids {
                let mut q = conn
                    .prepare("SELECT p.id FROM object_provider p WHERE p.is_delta=1 AND p.ref_target_oid=?1")
                    .unwrap();
                refdeps.extend(q.query_map(params![oid], |r| r.get(0)).unwrap().flatten());
            }
            for d in deps.into_iter().chain(refdeps) {
                if result.insert(d) {
                    stack.push(d);
                }
            }
        }
        result
    }
}

impl Engine {
    fn insert_provider(&self, tx: &rusqlite::Transaction, f: &PackEntry, file_id: i64) -> i64 {
        let (computed_oid, parse_code, parse_msg) = if !f.kind.is_delta() {
            let ctype = f.kind.content_type_name().unwrap();
            let oid = oid_sha1(ctype, &f.data);
            if f.inflated_size as usize != f.data.len() {
                (
                    oid_hex(&oid),
                    Some(crate::error::ErrorCode::DeltaSizeMismatch.as_str()),
                    Some(format!("header declares {} bytes but inflate produced {}", f.inflated_size, f.data.len())),
                )
            } else {
                (oid_hex(&oid), None, None)
            }
        } else {
            (String::new(), None, None)
        };
        tx.execute(
            "INSERT INTO object_provider\
            (kind,is_delta,source,file_id,pack_offset,claimed_oid,computed_oid,inflated_size,\
             header_size,compressed_len,payload,ofs_target_offset,ref_target_oid,parse_error_code,parse_error)\
             VALUES(?1,?2,?3,?4,?5,NULLIF(?6,''),?7,?8,?9,?10,?11,?12,?13,?14,?15)",
            params![
                f.kind as i64,
                f.kind.is_delta() as i64,
                SourceKind::Pack as i64,
                file_id,
                f.offset as i64,
                computed_oid,
                f.inflated_size as i64,
                f.header_size as i64,
                f.compressed_len as i64,
                f.data,
                f.offset as i64 - (f.ofs_target.map(|_| 0).unwrap_or(0)) * 0 + f.ofs_target.map(|v| v as i64).unwrap_or(0),
                f.ref_target.map(oid_hex),
                parse_code,
                parse_msg,
            ],
        )
        .unwrap() as i64
    }

    fn ingest_pack(&self, tx: &rusqlite::Transaction, file_id: i64, buf: &[u8], notes: &mut Vec<String>) -> i64 {
        let (info, errs) = match parse_pack(buf) {
            Ok(v) => v,
            Err(e) => {
                let sha = pack_sha1(&buf[..buf.len().saturating_sub(20)]);
                tx.execute(
                    "INSERT INTO pack_file(file_id,version,num_entries,pack_sha,parse_error) VALUES(?1,0,0,?2,?3)",
                    params![file_id, oid_hex(&sha), format!("{}", e)],
                )
                .unwrap();
                notes.push(format!("pack unparseable: {}", e));
                return 0;
            }
        };
        for (off, e) in &errs {
            notes.push(format!("entry @{} isolated: {}", off, e));
        }
        // verify whole-pack checksum (bytes before trailer)
        let computed = pack_sha1(&buf[..buf.len() - 20]);
        let checksum_ok = computed == info.trailing_sha;
        if !checksum_ok {
            notes.push("pack trailing SHA-1 mismatch".into());
        }
        tx.execute(
            "INSERT INTO pack_file(file_id,version,num_entries,pack_sha,parse_error) VALUES(?1,?2,?3,?4,?5)",
            params![
                file_id,
                info.version as i64,
                info.entries.len() as i64,
                oid_hex(&info.trailing_sha),
                if checksum_ok { None } else { Some("trailing sha1 mismatch") }
            ],
        )
        .unwrap();

        for e in &info.entries {
            self.insert_provider(tx, e, file_id);
        }
        info.entries.len() as i64
    }

    fn ingest_idx(&self, tx: &rusqlite::Transaction, file_id: i64, buf: &[u8], notes: &mut Vec<String>) {
        let idx = match parse_idx(buf) {
            Ok(i) => i,
            Err(e) => {
                notes.push(format!("idx unparseable: {}", e));
                tx.execute(
                    "INSERT INTO idx_file(file_id,version,num_records,pack_sha,idx_sha,parse_note) VALUES(?1,0,0,'','',?2)",
                    params![file_id, format!("{}", e)],
                )
                .unwrap();
                return;
            }
        };
        // Match a previously imported pack by checksum.
        let matched: Option<i64> = tx
            .query_row(
                "SELECT pf.file_id FROM pack_file pf WHERE pf.pack_sha=?1",
                params![oid_hex(&idx.pack_sha)],
                |r| r.get(0),
            )
            .optional()
            .unwrap();
        let mut note_parts: Vec<String> = Vec::new();
        if matched.is_none() {
            note_parts.push("no imported pack matches this idx checksum".into());
        }
        tx.execute(
            "INSERT INTO idx_file(file_id,version,num_records,pack_sha,idx_sha,matched_pack_file,parse_note) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                file_id,
                idx.version as i64,
                idx.records.len() as i64,
                oid_hex(&idx.pack_sha),
                oid_hex(&idx.idx_sha),
                matched,
                note_parts.join("; ")
            ],
        )
        .unwrap();

        // Attach oid + crc to providers; cross-check computed full-object ids.
        let mut offset_to_pid: HashMap<i64, i64> = HashMap::new();
        if let Some(pack_file) = matched {
            let mut s = tx
                .prepare("SELECT id, pack_offset FROM object_provider WHERE file_id=?1")
                .unwrap();
            for row in s.query_map(params![pack_file], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
            }).unwrap().flatten() {
                offset_to_pid.insert(row.1, row.0);
            }
        }
        for rec in &idx.records {
            let off = rec.offset as i64;
            if let Some(&pid) = offset_to_pid.get(&off) {
                let computed: Option<String> = tx
                    .query_row("SELECT computed_oid FROM object_provider WHERE id=?1", params![pid], |r| r.get(0))
                    .optional()
                    .unwrap()
                    .flatten()
                    .filter(|s: &String| !s.is_empty());
                let mismatch = computed.as_ref().map(|c| c != &oid_hex(&rec.oid)).unwrap_or(false);
                let (code, msg) = if mismatch {
                    (
                        Some(crate::error::ErrorCode::OidMismatch.as_str()),
                        Some(format!(
                            "idx claims {} but content hashes to {}",
                            oid_hex(&rec.oid),
                            computed.as_ref().unwrap()
                        )),
                    )
                } else {
                    (None, None)
                };
                tx.execute(
                    "UPDATE object_provider SET claimed_oid=?1, crc=?2, crc_ok=?3, parse_error_code=COALESCE(?4, parse_error_code), parse_error=COALESCE(?5, parse_error) WHERE id=?6",
                    params![oid_hex(&rec.oid), rec.crc as i64, if idx.version == 2 { 1 } else { 0 }, code, msg, pid],
                )
                .unwrap();
            } else {
                note_parts.push(format!("idx offset {} has no pack entry", off));
            }
        }
        // CRC verification requires reading the raw pack bytes from disk.
        if let Some(pack_file) = matched {
            self.verify_crcs(tx, pack_file, &idx.records, notes);
        }
        if !note_parts.is_empty() {
            notes.extend(note_parts);
        }
    }

    fn verify_crcs(&self, tx: &rusqlite::Transaction, pack_file: i64, records: &[crate::model::IdxRecord], notes: &mut Vec<String>) {
        let path_rel: String = tx
            .query_row("SELECT object_path FROM source_file WHERE id=?1", params![pack_file], |r| r.get(0))
            .unwrap();
        let buf = match std::fs::read(self.data_dir.join(&path_rel)) {
            Ok(b) => b,
            Err(_) => return,
        };
        for rec in records {
            let off = rec.offset as usize;
            let crc = crc32fast::hash(&buf[off..]);
            let ok = crc == rec.crc;
            tx.execute(
                "UPDATE object_provider SET crc=?1, crc_ok=?2 WHERE file_id=?3 AND pack_offset=?4",
                params![rec.crc as i64, ok as i64, pack_file, rec.offset as i64],
            )
            .unwrap();
            if !ok {
                notes.push(format!("bad CRC at pack offset {}", rec.offset));
                tx.execute(
                    "UPDATE object_provider SET parse_error_code='bad_crc', parse_error=?1 WHERE file_id=?2 AND pack_offset=?3",
                    params![
                        format!("crc32 {} does not match idx {}", crc, rec.crc),
                        pack_file,
                        rec.offset as i64
                    ],
                )
                .unwrap();
            }
        }
    }

    fn ingest_loose(&self, tx: &rusqlite::Transaction, file_id: i64, name: &str, buf: &[u8], notes: &mut Vec<String>) -> i64 {
        // Claimed oid from a path like ab/cdef... (38 more hex chars).
        let claimed = claimed_oid_from_path(name);
        let loose: LooseInfo = match parse_loose(buf) {
            Ok(l) => l,
            Err(e) => {
                notes.push(format!("loose object unparseable: {}", e));
                tx.execute(
                    "INSERT INTO loose_object(file_id,kind,declared_size,claimed_oid,parse_error) VALUES(?1,NULL,NULL,?2,?3)",
                    params![file_id, claimed, format!("{}", e)],
                )
                .unwrap();
                // still register a provider shell so the bad object is isolated
                tx.execute(
                    "INSERT INTO object_provider(kind,is_delta,source,file_id,pack_offset,claimed_oid,parse_error_code,parse_error)\
                     VALUES(3,0,?1,?2,-1,?3,?4,?5)",
                    params![SourceKind::Loose as i64, file_id, claimed, e.code.as_str(), e.message],
                )
                .unwrap();
                return 1;
            }
        };
        let computed = oid_sha1(loose.kind.content_type_name().unwrap(), &loose.content);
        let computed_hex = oid_hex(&computed);
        let mismatch = claimed.as_deref().map(|c| c != computed_hex).unwrap_or(false);
        tx.execute(
            "INSERT INTO loose_object(file_id,kind,declared_size,computed_oid,claimed_oid,content) VALUES(?1,?2,?3,?4,?5,?6)",
            params![file_id, loose.kind as i64, loose.inflated_size as i64, computed_hex, claimed, loose.content],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO object_provider(kind,is_delta,source,file_id,pack_offset,claimed_oid,computed_oid,inflated_size,payload) VALUES(?1,0,?2,?3,-1,?4,?5,?6,?7)",
            params![
                loose.kind as i64,
                SourceKind::Loose as i64,
                file_id,
                if mismatch { claimed.clone() } else { Some(computed_hex.clone()) },
                computed_hex,
                loose.inflated_size as i64,
                loose.content
            ],
        )
        .unwrap();
        if mismatch {
            notes.push(format!("loose object path oid {} differs from content oid {}", claimed.unwrap_or_default(), computed_hex));
        }
        1
    }
}

fn claimed_oid_from_path(name: &str) -> Option<String> {
    let p = name.replace('\\', "/");
    let parts: Vec<&str> = p.split('/').collect();
    if parts.len() >= 2 {
        let dir = parts[parts.len() - 2];
        let file = parts[parts.len() - 1];
        let cand = format!("{}{}", dir, file);
        if dir.len() == 2 && file.len() == 38 && cand.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(cand);
        }
    }
    None
}
