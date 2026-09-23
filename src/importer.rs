use crate::db::Store;
use crate::parser::{content_summary, parse_loose, parse_pack, DeltaRef};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
pub struct ImportReport {
    pub source_id: i64,
    pub kind: String,
    pub candidate_ids: Vec<i64>,
    pub errors: Vec<String>,
    pub affected_ids: Vec<i64>,
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

pub fn import_bytes(
    store: &Store,
    display_name: &str,
    data_dir: &Path,
    bytes: &[u8],
    paired_index: Option<&[u8]>,
) -> Result<ImportReport, String> {
    let kind = classify(display_name, bytes);
    std::fs::create_dir_all(data_dir).map_err(|err| err.to_string())?;
    let safe_name = display_name.replace(['/', '\\'], "_");
    let path = data_dir.join(safe_name);
    std::fs::write(&path, bytes).map_err(|err| err.to_string())?;
    let path_text = path.to_string_lossy().to_string();
    let source_id = store.upsert_source(
        display_name,
        &kind,
        &path_text,
        bytes.len() as i64,
        &sha256_hex(bytes),
    )?;

    let mut report = ImportReport {
        source_id,
        kind: kind.clone(),
        candidate_ids: Vec::new(),
        errors: Vec::new(),
        affected_ids: Vec::new(),
    };

    match kind.as_str() {
        "pack" => import_pack(store, source_id, bytes, paired_index, &mut report),
        "index" => report.errors.push("index imported as evidence; import its .pack to inspect entries".into()),
        "loose" => import_loose(store, source_id, display_name, bytes, &mut report),
        _ => {
            store.add_pack_error(source_id, "unknown_input", "unrecognized source", &content_summary(bytes).sha256)?;
            report.errors.push("unrecognized source".into());
        }
    }
    Ok(report)
}

fn classify(name: &str, bytes: &[u8]) -> String {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".pack") || bytes.starts_with(b"PACK") {
        "pack".into()
    } else if lower.ends_with(".idx") || bytes.starts_with(b"\xfftOc") {
        "index".into()
    } else if bytes.contains(&0) {
        "loose".into()
    } else {
        "unknown".into()
    }
}

fn import_pack(
    store: &Store,
    source_id: i64,
    bytes: &[u8],
    paired_index: Option<&[u8]>,
    report: &mut ImportReport,
) {
    let parsed = parse_pack(bytes, paired_index);
    for message in &parsed.errors {
        report.errors.push(message.clone());
        if let Err(err) = store.add_pack_error(source_id, "pack", message, &parsed.pack_checksum) {
            report.errors.push(err);
        }
    }
    let mut oid_by_offset: HashMap<u64, String> = HashMap::new();
    if let Some(idx) = &parsed.index {
        for message in &idx.errors {
            report.errors.push(message.clone());
            let _ = store.add_pack_error(source_id, "index", message, "fanout/index evidence");
        }
        for entry in &idx.entries {
            oid_by_offset.insert(entry.offset, entry.oid.clone());
        }
    }
    for entry in &parsed.entries {
        let oid = oid_by_offset
            .get(&entry.header_offset)
            .cloned()
            .unwrap_or_else(|| format!("unknown:pack{}:off{}", source_id, entry.header_offset));
        let location = format!("pack://{}/{}", source_id, entry.header_offset);
        let (delta_type, base_oid, target_offset) = match &entry.delta {
            DeltaRef::None => ("none", None, None),
            DeltaRef::Ofs {
                negative_offset,
                target_offset,
            } => (
                "ofs",
                oid_by_offset.get(target_offset).map(|value| value.as_str()),
                Some(*negative_offset as i64),
            ),
            DeltaRef::Ref { base_oid } => ("ref", Some(base_oid.as_str()), None),
        };
        let effective_base = match &entry.delta {
            DeltaRef::Ofs {
                target_offset, ..
            } => base_oid.or_else(|| {
                Some(
                    format!("unknown:pack{}:off{}", source_id, target_offset).as_str()
                        .to_string(),
                )
                    .as_deref()
            }),
            _ => base_oid,
        };
        let raw_payload = if matches!(entry.delta, DeltaRef::None) {
            entry.payload.clone()
        } else {
            Vec::new()
        };
        let delta_payload = if matches!(entry.delta, DeltaRef::None) {
            None
        } else {
            Some(entry.payload.as_slice())
        };
        let status = if entry.error.is_some() { "bad" } else { "queued" };
        match store.upsert_object(
            &oid,
            source_id,
            &location,
            Some(entry.index as i64),
            Some(entry.header_offset as i64),
            Some(entry.data_offset as i64),
            Some(entry.next_offset as i64),
            &entry.type_name,
            entry.declared_size as i64,
            entry.inflated_len as i64,
            delta_type,
            effective_base,
            match &entry.delta {
                DeltaRef::Ofs { target_offset, .. } => Some(*target_offset as i64),
                _ => None,
            },
            &raw_payload,
            delta_payload,
            status,
        ) {
            Ok(id) => {
                report.candidate_ids.push(id);
                if let Some(base) = effective_base {
                    let _ = store.insert_edge(
                        id,
                        base,
                        delta_type,
                        match &entry.delta {
                            DeltaRef::Ofs { target_offset, .. } => Some(*target_offset as i64),
                            _ => None,
                        },
                    );
                }
                if let Some(message) = &entry.error {
                    let evidence = format!(
                        "offset={} data={} declared={} inflated={} summary={:?}",
                        entry.header_offset,
                        entry.data_offset,
                        entry.declared_size,
                        entry.inflated_len,
                        content_summary(&entry.payload)
                    );
                    let _ = store.add_error(id, "entry", message, &evidence);
                }
            }
            Err(err) => report.errors.push(err),
        }
    }
}

fn import_loose(
    store: &Store,
    source_id: i64,
    name: &str,
    bytes: &[u8],
    report: &mut ImportReport,
) {
    let parsed = parse_loose(bytes);
    let stem = name
        .split('/')
        .next_back()
        .unwrap_or(name)
        .trim_end_matches(".loose")
        .replace('-', "");
    let supplied = if stem.len() == 40 && hex::decode(&stem).is_ok() {
        Some(stem)
    } else {
        None
    };
    let computed = if parsed.error.is_none() {
        crate::git::GitType::parse(&parsed.type_name)
            .map(|kind| hex::encode(crate::git::git_object_id(kind, &parsed.payload)))
    } else {
        None
    };
    let oid = supplied.or(computed).unwrap_or_else(|| format!("unknown:loose:{}", source_id));
    let location = format!("loose://{source_id}");
    let status = if parsed.error.is_some() { "bad" } else { "queued" };
    match store.upsert_object(
        &oid,
        source_id,
        &location,
        None,
        None,
        None,
        None,
        &parsed.type_name,
        parsed.declared_size as i64,
        parsed.inflated_len as i64,
        "none",
        None,
        None,
        &parsed.payload,
        None,
        status,
    ) {
        Ok(id) => {
            report.candidate_ids.push(id);
            if let Some(message) = &parsed.error {
                let _ = store.add_error(
                    id,
                    "loose",
                    message,
                    &format!("summary={:?}", content_summary(bytes)),
                );
            }
        }
        Err(err) => report.errors.push(err),
    }
}

pub fn load_existing(_data_dir: &Path) {}
