//! Import + low level parsing of loose objects, packs and v2 indexes.
//!
//! Parsing never shells out to git. Every parse error is captured on the
//! offending entry so one bad object never aborts analysis of the rest.

use std::collections::BTreeMap;

use rusqlite::params;

use crate::git::{crc32, inflate_from, read_obj_header, read_ofs_delta_offset, Kind};
use crate::model::{EntryError, ResolveError};
use crate::store::{NewEntry, Store};

/// Hard safety valve for a single inflated stream. Independent of the
/// reconstruction budget; anything larger is isolated, not trusted.
pub const INFLATE_HARD_CAP: usize = 512 * 1024 * 1024;

pub const PACK_MAGIC: &[u8; 4] = b"PACK";

#[derive(Debug, Default, Clone)]
pub struct IdxEntry {
    pub oid: String,
    pub offset: u64,
    pub crc: u32,
}

#[derive(Debug, Default)]
pub struct ParsedIdx {
    pub pack_sha: String,
    pub idx_checksum_ok: bool,
    pub fanout: Vec<i64>,
    pub entries: Vec<IdxEntry>,
    pub ordered: bool,
}

#[derive(Debug, Clone, Default)]
pub struct PackEntryMeta {
    pub offset: u64,
    pub type_code: u8,
    pub declared: u64,
    pub z_off: u64,
    pub z_len: u64,
    pub inflated_len: u64,
    pub delta: Option<&'static str>,
    pub base_oid: Option<String>,
    pub base_offset: Option<u64>,
    pub error: Option<EntryError>,
    pub inflated: Option<Vec<u8>>,
}

#[derive(Debug, Default)]
pub struct ParsedPack {
    pub count: u32,
    pub checksum_ok: bool,
    pub trailer_sha: String,
    pub metas: Vec<PackEntryMeta>,
}

fn err_json(e: &ResolveError) -> String {
    serde_json::to_string(e).unwrap_or_else(|_| "{}".into())
}

/// Parse and persist every object in a pack. Returns layout metadata even when
/// some entries are bad (those are recorded with `parse_err`).
pub fn parse_pack(bytes: &[u8]) -> Result<ParsedPack, String> {
    if bytes.len() < 32 {
        return Err("pack shorter than 32 bytes".into());
    }
    if &bytes[0..4] != PACK_MAGIC {
        return Err("bad pack magic".into());
    }
    let version = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if version != 2 {
        return Err(format!("unsupported pack version {version}"));
    }
    let count = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    let end = bytes.len() - 20;
    let trailer_sha = hex::encode(&bytes[end..end + 20]);
    let checksum_ok = {
        use sha1::Digest;
        let mut h = sha1::Sha1::new();
        h.update(&bytes[..end]);
        hex::encode(h.finalize()) == trailer_sha
    };

    let mut out = ParsedPack {
        count,
        checksum_ok,
        trailer_sha,
        metas: Vec::new(),
    };

    let mut pos = 12usize;
    let mut seen = 0u32;
    while pos < end {
        let offset = pos as u64;
        let (type_code, declared, hdr_len) = match read_obj_header(bytes, pos) {
            Ok(v) => v,
            Err(e) => {
                out.metas.push(PackEntryMeta {
                    offset,
                    type_code: 0,
                    declared: 0,
                    z_off: pos as u64,
                    z_len: 0,
                    inflated_len: 0,
                    error: Some(EntryError::Inflate(format!("object header: {e}"))),
                    ..Default::default()
                });
                break; // cannot locate the next object without a header
            }
        };
        pos += hdr_len;

        let mut meta = PackEntryMeta {
            offset,
            type_code,
            declared,
            z_off: pos as u64,
            ..Default::default()
        };

        match type_code {
            6 => {
                meta.delta = Some("ofs-delta");
                match read_ofs_delta_offset(bytes, pos) {
                    Ok((neg, used)) => {
                        pos += used;
                        meta.z_off = pos as u64;
                        meta.base_offset = Some(offset.saturating_sub(neg));
                        if neg > offset {
                            meta.error = Some(EntryError::OfsOutOfBounds {
                                neg,
                                pack_size: end as u64,
                            });
                        }
                    }
                    Err(e) => {
                        meta.error = Some(EntryError::Inflate(format!("ofs header: {e}")));
                        out.metas.push(meta);
                        break;
                    }
                }
            }
            7 => {
                meta.delta = Some("ref-delta");
                if pos + 20 > end {
                    meta.error = Some(EntryError::Inflate("ref-delta base oid truncated".into()));
                    out.metas.push(meta);
                    break;
                }
                meta.base_oid = Some(hex::encode(&bytes[pos..pos + 20]));
                pos += 20;
                meta.z_off = pos as u64;
            }
            1..=4 => {}
            other => meta.error = Some(EntryError::UnknownType(other)),
        }

        let start_z = pos;
        match inflate_from(bytes, start_z, declared, INFLATE_HARD_CAP) {
            Ok(inf) => {
                meta.z_len = inf.consumed as u64;
                meta.inflated_len = inf.data.len() as u64;
                pos = start_z + inf.consumed;
                if type_code >= 1 && type_code <= 7 && inf.data.len() as u64 != declared {
                    // Spoofed declared size only meaningful for canonical types
                    // (deltas use their own size encoding).
                    if (1..=4).contains(&type_code) {
                        meta.error = Some(EntryError::SizeSpoof {
                            declared,
                            actual: inf.data.len() as u64,
                        });
                    }
                }
                meta.inflated = Some(inf.data);
            }
            Err(e) => {
                if meta.error.is_none() {
                    meta.error = Some(EntryError::Inflate(e));
                } else {
                    // keep the structural error; still record zero zlen
                }
                out.metas.push(meta);
                break; // cannot find boundary without successful inflate
            }
        }
        out.metas.push(meta);
        seen += 1;
        if seen >= count {
            break;
        }
    }

    Ok(out)
}


/// Parse a v2 pack index (.idx) purely from bytes.
pub fn parse_idx(bytes: &[u8]) -> Result<ParsedIdx, String> {
    if bytes.len() < 8 {
        return Err("idx shorter than 8 bytes".into());
    }
    // v2: magic \377tOc + version 2. v1 has no magic and is not supported.
    if &bytes[0..4] != b"\xfftOc" {
        return Err("only idx v2 is supported (bad magic)".into());
    }
    let ver = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if ver != 2 {
        return Err(format!("unsupported idx version {ver}"));
    }
    let mut pos = 8usize;
    let mut fanout = Vec::with_capacity(256);
    let mut prev = 0i64;
    let mut ordered = true;
    for _ in 0..256 {
        if pos + 4 > bytes.len() {
            return Err("fanout truncated".into());
        }
        let v = i64::from(u32::from_be_bytes([
            bytes[pos],
            bytes[pos + 1],
            bytes[pos + 2],
            bytes[pos + 3],
        ]));
        if v < prev {
            ordered = false;
        }
        prev = v;
        fanout.push(v);
        pos += 4;
    }
    let n = *fanout.last().unwrap() as usize;

    let need = n * (20 + 4 + 4) + 40;
    if pos + need > bytes.len() {
        return Err(format!("idx too small for {n} entries"));
    }

    let mut entries = Vec::with_capacity(n);
    let mut last_oid: Option<[u8; 20]> = None;
    for _ in 0..n {
        let mut o = [0u8; 20];
        o.copy_from_slice(&bytes[pos..pos + 20]);
        if let Some(l) = last_oid {
            if o <= l {
                ordered = false;
            }
        }
        last_oid = Some(o);
        entries.push(IdxEntry {
            oid: hex::encode(o),
            offset: 0,
            crc: 0,
        });
        pos += 20;
    }
    for i in 0..n {
        let crc = u32::from_be_bytes([
            bytes[pos],
            bytes[pos + 1],
            bytes[pos + 2],
            bytes[pos + 3],
        ]);
        entries[i].crc = crc;
        pos += 4;
    }
    for i in 0..n {
        let off = u32::from_be_bytes([
            bytes[pos],
            bytes[pos + 1],
            bytes[pos + 2],
            bytes[pos + 3],
        ]);
        pos += 4;
        if off & 0x8000_0000 != 0 {
            let level = (off & 0x7fff_ffff) as usize;
            let lbase = 8 + 256 * 4 + n * (20 + 4 + 4);
            let lo = lbase + level * 8;
            if lo + 8 > bytes.len() - 40 {
                return Err("64-bit offset table index out of range".into());
            }
            entries[i].offset = u64::from_be_bytes(bytes[lo..lo + 8].try_into().unwrap());
        } else {
            entries[i].offset = u64::from(off);
        }
    }

    let checksum_tail = bytes.len() - 40;
    let pack_sha = hex::encode(&bytes[checksum_tail..checksum_tail + 20]);
    let idx_trailer = hex::encode(&bytes[checksum_tail + 20..checksum_tail + 40]);
    let idx_checksum_ok = {
        use sha1::Digest;
        let mut h = sha1::Sha1::new();
        h.update(&bytes[..checksum_tail + 20]);
        hex::encode(h.finalize()) == idx_trailer
    };

    Ok(ParsedIdx {
        pack_sha,
        idx_checksum_ok,
        fanout,
        entries,
        ordered,
    })
}

/// Parse a loose object's zlib stream: `<type> <size>\0<content>`.
pub fn parse_loose(bytes: &[u8]) -> Result<(Kind, Vec<u8>), EntryError> {
    let inf = inflate_from(bytes, 0, 0, INFLATE_HARD_CAP)
        .map_err(EntryError::Inflate)?;
    let nul = inf
        .data
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| EntryError::Inflate("loose header missing NUL".into()))?;
    let header = std::str::from_utf8(&inf.data[..nul])
        .map_err(|_| EntryError::Inflate("loose header not utf8".into()))?;
    let (t, l) = header
        .split_once(' ')
        .ok_or_else(|| EntryError::Inflate("loose header malformed".into()))?;
    let kind = match t {
        "blob" => Kind::Blob,
        "tree" => Kind::Tree,
        "commit" => Kind::Commit,
        "tag" => Kind::Tag,
        _ => return Err(EntryError::UnknownType(0)),
    };
    let size: u64 = l
        .parse()
        .map_err(|_| EntryError::Inflate("loose size not numeric".into()))?;
    let content = inf.data[nul + 1..].to_vec();
    if content.len() as u64 != size {
        return Err(EntryError::SizeSpoof {
            declared: size,
            actual: content.len() as u64,
        });
    }
    Ok((kind, content))
}

/// Persist entries parsed from a pack. Inflated payloads are kept on disk under
/// `inflated/` so resolution never re-inflates.
pub fn persist_pack(store: &Store, source_id: i64, parsed: &ParsedPack) -> rusqlite::Result<Vec<i64>> {
    use rusqlite::params;
    let mut ids = Vec::new();
    let dir = store.data_dir.join("inflated");
    std::fs::create_dir_all(&dir).ok();
    for m in &parsed.metas {
        let mut ne = NewEntry {
            source_id,
            offset: Some(m.offset as i64),
            type_code: Some(m.type_code as i64),
            delta: m.delta.map(|s| s.to_string()),
            base_oid: m.base_oid.clone(),
            base_offset: m.base_offset.map(|v| v as i64),
            declared_size: Some(m.declared as i64),
            inflated_size: Some(m.inflated_len as i64),
            z_off: Some(m.z_off as i64),
            z_len: Some(m.z_len as i64),
            ..Default::default()
        };
        if let Some(e) = &m.error {
            ne.parse_err = Some(err_json(&ResolveError::Entry(e.clone())));
        }
        if matches!(m.type_code, 1..=4) {
            ne.type_name = Kind::from_code(m.type_code).map(|k| k.name().to_string());
        }
        if let Some(data) = &m.inflated {
            ne.sha256 = crate::store::sha256_hex(data);
        }
        let id = store.insert_entry(&ne)?;
        if let Some(data) = &m.inflated {
            let rel = format!("inflated/s{source_id}_e{id}");
            let _ = std::fs::write(store.data_dir.join(&rel), data);
            store.db.execute(
                "UPDATE entries SET sha256=?2 WHERE id=?1",
                params![id, ne.sha256],
            )?;
        }
        ids.push(id);
    }
    Ok(ids)
}

pub fn persist_loose(
    store: &Store,
    source_id: i64,
    claimed: Option<&str>,
    parsed: std::result::Result<(Kind, Vec<u8>), EntryError>,
    raw_len: u64,
) -> rusqlite::Result<i64> {
    let mut ne = NewEntry {
        source_id,
        offset: None,
        ..Default::default()
    };
    ne.z_off = Some(0);
    ne.z_len = Some(raw_len as i64);
    match parsed {
        Ok((kind, content)) => {
            ne.type_code = Some(match kind {
                Kind::Commit => 1,
                Kind::Tree => 2,
                Kind::Blob => 3,
                Kind::Tag => 4,
            });
            ne.type_name = Some(kind.name().to_string());
            ne.declared_size = Some(content.len() as i64);
            ne.inflated_size = Some(content.len() as i64);
            ne.claimed_oid = claimed.map(String::from);
            ne.sha256 = crate::store::sha256_hex(&content);
            let id = store.insert_entry(&ne)?;
            let _ = std::fs::create_dir_all(store.data_dir.join("inflated"));
            let rel = format!("inflated/s{source_id}_e{id}");
            let _ = std::fs::write(store.data_dir.join(&rel), &content);
            Ok(id)
        }
        Err(e) => {
            ne.parse_err = Some(err_json(&ResolveError::Entry(e)));
            store.insert_entry(&ne)
        }
    }
}

/// Reassociate every idx with its pack (by pack sha), apply fanout + claimed
/// oids, and verify per-entry CRC32 and offsets.
pub fn relink(store: &Store) -> rusqlite::Result<()> {
    let mut packs: BTreeMap<String, (i64, i64)> = BTreeMap::new();
    {
        let mut stmt = store
            .db
            .prepare("SELECT id, COALESCE(pack_sha,'') FROM sources WHERE kind='pack'")?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?;
        for row in rows {
            let (id, sha) = row?;
            packs.insert(sha, (id, 0));
        }
    }

    // reset stale annotation from idxes
    store.db.execute(
        "UPDATE entries SET claimed_oid=NULL WHERE source_id IN
            (SELECT id FROM sources WHERE kind='idx')",
        [],
    )?;

    let mut stmt = store.db.prepare(
        "SELECT id,name,path,COALESCE(pack_sha,''),COALESCE(idx_sha,'')
         FROM sources WHERE kind='idx'",
    )?;
    let idxes: Vec<(i64, String, String, String, String)> = stmt
        .query_map([], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(stmt);

    for (idx_id, _name, rel, idx_pack_sha, idx_sha) in idxes {
        let bytes = match std::fs::read(store.data_dir.join(&rel)) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let parsed = match parse_idx(&bytes) {
            Ok(p) => p,
            Err(msg) => {
                store.set_source_meta(idx_id, Some(false), None, Some(&msg), None)?;
                continue;
            }
        };
        let fan: Vec<(i64, i64)> = parsed
            .fanout
            .iter()
            .enumerate()
            .map(|(b, c)| (b as i64, *c))
            .collect();
        store.replace_fanout(idx_id, &fan)?;

        let mismatch = if idx_pack_sha.is_empty() {
            // not previously linked; link by pack sha
            match packs.get(&parsed.pack_sha) {
                Some((pack_id, _)) => {
                    store.db.execute(
                        "UPDATE sources SET pack_sha=?2, idx_sha=?3, idx_ok=?4 WHERE id=?1",
                        params![idx_id, parsed.pack_sha, idx_sha, true],
                    )?;
                    false
                }
                None => {
                    store.db.execute(
                        "UPDATE sources SET idx_ok=?2 WHERE id=?1",
                        params![idx_id, false],
                    )?;
                    true
                }
            }
        } else {
            idx_pack_sha != parsed.pack_sha
        };

        let pack_id = packs.get(&parsed.pack_sha).map(|x| x.0);
        let pack_bytes = match pack_id {
            Some(pid) => {
                let p: String = store.db.query_row(
                    "SELECT path FROM sources WHERE id=?1",
                    params![pid],
                    |r| r.get(0),
                )?;
                std::fs::read(store.data_dir.join(p)).ok()
            }
            None => None,
        };

        // offset -> pack entry id
        let mut off2entry: BTreeMap<u64, i64> = BTreeMap::new();
        if let Some(pid) = pack_id {
            let mut es = store.db.prepare(
                "SELECT id,offset FROM entries WHERE source_id=?1 AND offset IS NOT NULL",
            )?;
            let rows = es.query_map(params![pid], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
            })?;
            for r in rows {
                let (eid, off) = r?;
                off2entry.insert(off as u64, eid);
            }
        }

        let mut crc_rows: Vec<(i64, u32, u32, bool)> = Vec::new();
        let mut any_crc_bad = false;
        let mut any_missing_off = false;
        for ie in &parsed.entries {
            if let Some(&eid) = off2entry.get(&ie.offset) {
                store.db.execute(
                    "UPDATE entries SET claimed_oid=?2 WHERE id=?1",
                    params![eid, ie.oid],
                )?;
            } else {
                any_missing_off = true;
            }
            if let Some(pb) = &pack_bytes {
                // CRC covers from the object header through compressed data.
                // We derive the span from pack entry metadata.
                if let Some(&eid) = off2entry.get(&ie.offset) {
                    let (zlen,): (Option<i64>,) = store.db.query_row(
                        "SELECT z_len FROM entries WHERE id=?1",
                        params![eid],
                        |r| Ok((r.get(0)?,)),
                    )?;
                    // need z_len relative end; header length = z_off-offset+zlen
                    let (zoff,): (Option<i64>,) = store.db.query_row(
                        "SELECT z_off FROM entries WHERE id=?1",
                        params![eid],
                        |r| Ok((r.get(0)?,)),
                    )?;
                    if let (Some(zlen), Some(zoff)) = (zlen, zoff) {
                        let span_end = (zoff + zlen) as usize;
                        let start = ie.offset as usize;
                        if span_end <= pb.len() {
                            let actual = crc32(&pb[start..span_end]);
                            let ok = actual == ie.crc;
                            if !ok {
                                any_crc_bad = true;
                            }
                            crc_rows.push((ie.offset as i64, ie.crc, actual, ok));
                        }
                    }
                }
            }
        }
        store.replace_crc(idx_id, &crc_rows)?;

        let mut problems: Vec<String> = Vec::new();
        if !parsed.idx_checksum_ok {
            problems.push("idx trailer checksum mismatch".into());
        }
        if !parsed.ordered {
            problems.push("oid table not strictly sorted".into());
        }
        if mismatch {
            problems.push(format!(
                "idx pack_sha {} does not match paired pack {}",
                parsed.pack_sha,
                idx_pack_sha
            ));
        }
        if any_crc_bad {
            problems.push("one or more object CRC32 mismatch".into());
        }
        if any_missing_off {
            problems.push("idx references offsets absent from pack".into());
        }
        let idx_ok = problems.is_empty();
        let joined: Option<String> = (!problems.is_empty()).then(|| problems.join("; "));
        store.set_source_meta(
            idx_id,
            Some(idx_ok),
            None,
            joined.as_deref(),
            Some(&parsed.pack_sha),
        )?;
    }
    Ok(())
}
