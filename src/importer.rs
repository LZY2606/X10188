//! 导入管线：嗅探类型 -> 保存原文件到数据目录 -> 解析 -> 入库 -> 触发（增量）重算。
//!
//! 关键设计：
//! * 原文件始终保留（内容摘要 sha1 + 原始偏移都在 DB 中）；
//! * pack 与 idx 通过“pack 尾部 20 字节校验和”配套；idx 先到也能在 pack 补入后匹配；
//! * 同一个 pack 重复导入 / idx 后到，都会触发仅受影响子图的重算；
//! * 导入顺序不会改变候选排序（排序键完全确定，见 resolver::sort_candidates）。

use std::path::Path;

use serde::Serialize;

use crate::hash::{sha1_hex, parse_oid_hex};
use crate::idx::parse_idx_v2;
use crate::loose::{looks_like_loose_path, parse_loose};
use crate::pack::{parse_pack_sequential, parse_pack_with_offsets, PACK_MAGIC};
use crate::store::{ev_json, idx_pack_checksum, obj_code, pack_trailer, NewCandidate, SourceKind, Store};
use crate::types::ObjType;
use crate::{pack, resolver};

#[derive(Debug, Clone, Serialize)]
pub struct ImportReport {
    pub source_id: i64,
    pub kind: String,
    pub filename: String,
    pub sha1: String,
    pub size_bytes: i64,
    pub objects: usize,
    pub evidence: Vec<serde_json::Value>,
    pub matched_pack_source_id: Option<i64>,
    pub resolve: Option<resolver::ResolveSummary>,
    pub incremental: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sniffed {
    Pack,
    Idx,
    Loose,
    Unknown,
}

pub fn sniff(buf: &[u8], filename: &str) -> Sniffed {
    if buf.len() >= 4 && &buf[0..4] == PACK_MAGIC {
        return Sniffed::Pack;
    }
    if crate::idx::looks_like_idx_v2(buf) {
        return Sniffed::Idx;
    }
    // loose: 路径像 ab/cdef… 或内容能按 loose 解出合法头。
    if looks_like_loose_path(filename) {
        return Sniffed::Loose;
    }
    if buf.len() >= 2 && (buf[0] & 0x0f) == 8 {
        if let Ok(inf) = crate::zlib::inflate_stream(buf, 0, None) {
            if let Some(nul) = inf.data.iter().position(|&b| b == 0) {
                let head = String::from_utf8_lossy(&inf.data[..nul]);
                if head.split(' ').count() == 2 {
                    return Sniffed::Loose;
                }
            }
        }
    }
    Sniffed::Unknown
}

pub struct Importer<'a> {
    store: &'a Store,
}

impl<'a> Importer<'a> {
    pub fn new(store: &'a Store) -> Self {
        Importer { store }
    }

    pub fn import_bytes(&self, filename: &str, data: &[u8]) -> ImportReport {
        let sniffed = sniff(data, filename);
        let sha1 = sha1_hex(data);
        let safe = safe_filename(filename);
        let stored_rel = format!("files/{}_{safe}", &sha1[..10]);
        let stored_abs = format!("{}/{}", self.store.data_dir, stored_rel);
        std::fs::write(&stored_abs, data).expect("写入数据目录失败");

        match sniffed {
            Sniffed::Pack => self.import_pack(filename, &stored_rel, data, &sha1),
            Sniffed::Idx => self.import_idx(filename, &stored_rel, data, &sha1),
            Sniffed::Loose => self.import_loose(filename, &stored_rel, data, &sha1),
            Sniffed::Unknown => self.import_unknown(filename, &stored_rel, data, &sha1),
        }
    }

    fn import_pack(&self, filename: &str, stored_rel: &str, data: &[u8], sha1: &str) -> ImportReport {
        // 先找是否已有配套 idx（idx.pack_checksum == 本 pack trailer）。
        let trailer = if data.len() >= 20 { Some(hex::encode(&data[data.len() - 20..])) } else { None };
        let idx_src = trailer.as_ref().and_then(|t| {
            self.store
                .sources()
                .into_iter()
                .find(|s| s.kind == "idx" && s.idx_pack_checksum.as_deref() == Some(t.as_str()))
        });

        let result = if let Some(idx) = &idx_src {
            // 需要读回 idx 原文件拿 offset 表；我们只需要 offset，因此重新解析其内容。
            let idx_path = format!("{}/{}", self.store.data_dir, idx.stored_path);
            let idx_buf = std::fs::read(&idx_path).unwrap_or_default();
            let idx_report = parse_idx_v2(&idx_buf);
            let offsets: Vec<u64> = idx_report.entries.iter().map(|e| e.offset).collect();
            parse_pack_with_offsets(data, &offsets)
        } else {
            parse_pack_sequential(data)
        };

        let mut evidence = result.report.evidence.clone();
        let source_id = self.store.insert_source(
            SourceKind::Pack,
            filename,
            stored_rel,
            data.len() as i64,
            sha1,
            pack_trailer(&result.report).as_deref(),
            None,
            if evidence.is_empty() { "parsed" } else { "parsed_with_evidence" },
            &evidence,
        );

        let idx_entries: std::collections::HashMap<u64, (String, u32)> = match &idx_src {
            Some(idx) => {
                let idx_path = format!("{}/{}", self.store.data_dir, idx.stored_path);
                let idx_buf = std::fs::read(&idx_path).unwrap_or_default();
                parse_idx_v2(&idx_buf)
                    .entries
                    .into_iter()
                    .map(|e| (e.offset, (e.oid, e.crc32)))
                    .collect()
            }
            None => std::collections::HashMap::new(),
        };

        let mut new_base_ids = Vec::new();
        for pe in &result.parsed {
            let e = &pe.entry;
            let abs_comp = e.comp_offset as usize;
            let comp_bytes = e.comp_len.map(|l| &data[abs_comp..abs_comp + l as usize]);
            let mut entry_ev = e.evidence.clone();
            let mut expected_oid = None;

            if let Some((oid, want_crc)) = idx_entries.get(&e.offset) {
                expected_oid = Some(oid.clone());
                if let Some(cb) = comp_bytes {
                    let got = crc32fast::hash(cb);
                    if got != *want_crc {
                        entry_ev.push(crate::types::Evidence::new(
                            "crc_mismatch",
                            format!("index 期望 CRC32 {want_crc:08x}，压缩数据实算 {got:08x}"),
                            Some(e.comp_offset),
                            e.comp_len,
                        ));
                    }
                }
            }

            let is_delta = matches!(e.stype, ObjType::OfsDelta | ObjType::RefDelta);
            let nc = NewCandidate {
                source_id,
                kind: "packed",
                pack_offset: Some(e.offset as i64),
                header_len: Some(e.header_len as i64),
                meta_len: Some(e.meta_len as i64),
                comp_offset: Some(e.comp_offset as i64),
                comp_len: e.comp_len.map(|v| v as i64),
                stype: obj_code(e.stype),
                declared_size: e.declared_size as i64,
                inflated_size: e.inflated_size.map(|v| v as i64),
                delta: is_delta,
                base_offset: e.base_offset.map(|v| v as i64),
                base_oid: e.base_oid.clone(),
                delta_payload: if is_delta { &pe.inflated } else { &[] },
                body: if is_delta { &[] } else { &pe.inflated },
                evidence: &entry_ev,
                expected_oid,
            };
            let cid = self.store.insert_candidate(&nc);
            if !is_delta {
                new_base_ids.push(cid);
            }
            // 解压失败的条目标记解析错误（隔离）。
            if e.inflated_size.is_none() || entry_ev.iter().any(|x| x.code == "size_spoof" || x.code == "truncated_zlib" || x.code == "crc_mismatch") {
                self.store.mark_candidate_parse_error(cid);
            }
            evidence.extend(entry_ev.clone());
        }

        self.store.recompute_rank_scores();

        // 配套 idx 到达/存在：用 index 的 oid 回填（insert 时已传 expected_oid，但只写入非 delta 的 oid）。
        // delta 的 oid 也由 index 给出，用于最终校验。
        for (off, (oid, _)) in &idx_entries {
            self.store.set_pack_oid(source_id, *off as i64, oid);
        }

        // 有配套 idx：对象的 oid 已知，但 delta 链仍要在本包内还原，
        // 走全量 resolve（顺序、memo 复用）；无 idx 同理。补入 base 的“局部重算”
        // 只发生在 loose 补入 或 idx 后到 两种场景。
        let incremental = false;
        let resolve = self.run_resolve(RunMode::Full);

        ImportReport {
            source_id,
            kind: "pack".into(),
            filename: filename.into(),
            sha1: sha1.into(),
            size_bytes: data.len() as i64,
            objects: result.parsed.len(),
            evidence: parse_ev(&evidence),
            matched_pack_source_id: idx_src.as_ref().map(|s| s.id),
            resolve,
            incremental,
        }
    }

    fn import_idx(&self, filename: &str, stored_rel: &str, data: &[u8], sha1: &str) -> ImportReport {
        let report = parse_idx_v2(data);
        let pack_checksum = idx_pack_checksum(&report);
        let evidence = report.evidence.clone();
        let source_id = self.store.insert_source(
            SourceKind::Idx,
            filename,
            stored_rel,
            data.len() as i64,
            sha1,
            None,
            pack_checksum.as_deref(),
            if evidence.is_empty() { "parsed" } else { "parsed_with_evidence" },
            &evidence,
        );

        // idx 先到：暂无可匹配 pack，不产生候选。pack 后到时会回头读取该 idx。
        let matched_pack = pack_checksum.as_ref().and_then(|pc| {
            self.store.sources().into_iter().find(|s| s.kind == "pack" && s.pack_checksum.as_deref() == Some(pc.as_str()))
        });

        let mut new_base_ids = Vec::new();
        if let Some(pack_src) = &matched_pack {
            // 重新解析对应 pack（此时用 index offsets），幂等替换候选并校验 CRC。
            let pack_path = format!("{}/{}", self.store.data_dir, pack_src.stored_path);
            if let Ok(pack_buf) = std::fs::read(&pack_path) {
                let offsets: Vec<u64> = report.entries.iter().map(|e| e.offset).collect();
                let presult = parse_pack_with_offsets(&pack_buf, &offsets);
                let idx_map: std::collections::HashMap<u64, (String, u32)> =
                    report.entries.iter().map(|e| (e.offset, (e.oid.clone(), e.crc32))).collect();
                for pe in &presult.parsed {
                    let e = &pe.entry;
                    let abs = e.comp_offset as usize;
                    let comp = e.comp_len.map(|l| &pack_buf[abs..abs + l as usize]);
                    let mut entry_ev = e.evidence.clone();
                    let expected_oid = idx_map.get(&e.offset).map(|(o, _)| o.clone());
                    if let Some((_, want)) = idx_map.get(&e.offset) {
                        if let Some(cb) = comp {
                            let got = crc32fast::hash(cb);
                            if got != *want {
                                entry_ev.push(crate::types::Evidence::new(
                                    "crc_mismatch",
                                    format!("index 期望 CRC32 {want:08x}，实算 {got:08x}"),
                                    Some(e.comp_offset),
                                    e.comp_len,
                                ));
                            }
                        }
                    }
                    let is_delta = matches!(e.stype, ObjType::OfsDelta | ObjType::RefDelta);
                    let nc = NewCandidate {
                        source_id: pack_src.id,
                        kind: "packed",
                        pack_offset: Some(e.offset as i64),
                        header_len: Some(e.header_len as i64),
                        meta_len: Some(e.meta_len as i64),
                        comp_offset: Some(e.comp_offset as i64),
                        comp_len: e.comp_len.map(|v| v as i64),
                        stype: obj_code(e.stype),
                        declared_size: e.declared_size as i64,
                        inflated_size: e.inflated_size.map(|v| v as i64),
                        delta: is_delta,
                        base_offset: e.base_offset.map(|v| v as i64),
                        base_oid: e.base_oid.clone(),
                        delta_payload: if is_delta { &pe.inflated } else { &[] },
                        body: if is_delta { &[] } else { &pe.inflated },
                        evidence: &entry_ev,
                        expected_oid,
                    };
                    let cid = self.store.insert_candidate(&nc);
                    if !is_delta {
                        new_base_ids.push(cid);
                    }
                    if entry_ev.iter().any(|x| matches!(x.code.as_str(), "size_spoof" | "truncated_zlib" | "crc_mismatch")) {
                        self.store.mark_candidate_parse_error(cid);
                    }
                }
                self.store.recompute_rank_scores();
                for (off, (oid, _)) in &idx_map {
                    self.store.set_pack_oid(pack_src.id, *off as i64, oid);
                }
            }
        }

        let resolve = if matched_pack.is_some() {
            self.run_resolve(RunMode::Full)
        } else {
            self.run_resolve(RunMode::Empty)
        };
        ImportReport {
            source_id,
            kind: "idx".into(),
            filename: filename.into(),
            sha1: sha1.into(),
            size_bytes: data.len() as i64,
            objects: report.entries.len(),
            evidence: parse_ev(&evidence),
            matched_pack_source_id: matched_pack.as_ref().map(|s| s.id),
            resolve,
            incremental: true,
        }
    }

    fn import_loose(&self, filename: &str, stored_rel: &str, data: &[u8], sha1: &str) -> ImportReport {
        // 从路径 ab/cdef... 推期望 oid。
        let path_oid = Path::new(filename)
            .file_name()
            .zip(Path::new(filename).parent().and_then(|p| p.file_name()))
            .map(|(name, dir)| format!("{}{}", dir.to_string_lossy(), name.to_string_lossy()))
            .filter(|s| parse_oid_hex(s).is_some());

        let report = parse_loose(data, path_oid.as_deref());
        let source_id = self.store.insert_source(
            SourceKind::Loose,
            filename,
            stored_rel,
            data.len() as i64,
            sha1,
            None,
            None,
            if report.evidence.is_empty() { "parsed" } else { "parsed_with_evidence" },
            &report.evidence,
        );

        let oid = report.oid.clone();
        let nc = NewCandidate {
            source_id,
            kind: "loose",
            pack_offset: None,
            header_len: None,
            meta_len: None,
            comp_offset: Some(0),
            comp_len: Some(data.len() as i64),
            stype: obj_code(report.obj_type),
            declared_size: report.declared_size as i64,
            inflated_size: Some(report.inflated_size as i64),
            delta: false,
            base_offset: None,
            base_oid: None,
            delta_payload: &[],
            body: &report.body,
            evidence: &report.evidence,
            expected_oid: oid.clone(),
        };
        let cid = self.store.insert_candidate(&nc);
        if report.evidence.iter().any(|e| e.code == "oid_mismatch" || e.code == "size_spoof") {
            self.store.mark_candidate_parse_error(cid);
        }
        self.store.recompute_rank_scores();

        // 补入 base：只重算依赖这个 oid 的子图（加上 loose 自身这个新 base）。
        let changed = if let Some(o) = oid.clone() {
            let mut ids: Vec<i64> = self.store.all_dependents_via_base_oid(&o).iter().map(|c| c.id).collect();
            ids.push(cid);
            ids
        } else {
            vec![cid]
        };
        let resolve = self.run_resolve(RunMode::Subgraph(changed));

        ImportReport {
            source_id,
            kind: "loose".into(),
            filename: filename.into(),
            sha1: sha1.into(),
            size_bytes: data.len() as i64,
            objects: 1,
            evidence: parse_ev(&report.evidence),
            matched_pack_source_id: None,
            resolve,
            incremental: true,
        }
    }

    fn import_unknown(&self, filename: &str, stored_rel: &str, data: &[u8], sha1: &str) -> ImportReport {
        let ev = vec![crate::types::Evidence::new(
            "unrecognized_format",
            "无法识别为 pack / idx / loose object，已原样保留但不产生候选",
            None,
            Some(data.len() as u64),
        )];
        let source_id =
            self.store.insert_source(SourceKind::Unknown, filename, stored_rel, data.len() as i64, sha1, None, None, "unrecognized", &ev);
        ImportReport {
            source_id,
            kind: "unknown".into(),
            filename: filename.into(),
            sha1: sha1.into(),
            size_bytes: data.len() as i64,
            objects: 0,
            evidence: parse_ev(&ev),
            matched_pack_source_id: None,
            resolve: None,
            incremental: false,
        }
    }

    /// 增量重算模式。
    fn run_resolve(&self, mode: RunMode) -> Option<resolver::ResolveSummary> {
        match mode {
            RunMode::Full => resolver::resolve_branch(self.store, crate::store::DEFAULT_BRANCH),
            RunMode::Subgraph(ids) => resolver::resolve_subgraph(self.store, crate::store::DEFAULT_BRANCH, &ids),
            RunMode::Empty => None,
        }
    }
}

enum RunMode {
    Full,
    Subgraph(Vec<i64>),
    Empty,
}

fn safe_filename(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

fn parse_ev(ev: &[crate::types::Evidence]) -> Vec<serde_json::Value> {
    serde_json::from_str(&ev_json(ev)).unwrap_or_default()
}

// 兼容保留：允许上层直接引用 pack 模块。
/// 删除源文件前，返回仍依赖它的对象（用于 UI 确认）。
pub fn dependents_before_delete(store: &Store, source_id: i64) -> Vec<i64> {
    // 该源提供的候选 id
    let own_ids: std::collections::HashSet<i64> = store.candidate_ids_of_source(source_id).into_iter().collect();
    // 其他源中，base 解析后落到这些候选上的 delta（通过 edges 查）。
    let mut deps = Vec::new();
    for c in store.all_candidates() {
        if own_ids.contains(&c.id) {
            continue;
        }
        if c.source_id == source_id {
            continue;
        }
        let uses = store.edges_pointing_into(&c.id, &own_ids);
        if uses {
            deps.push(c.id);
        }
    }
    deps
}
