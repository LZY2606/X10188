use rusqlite::params;
use serde::Serialize;

use crate::git;

#[derive(Debug, Serialize, Default)]
pub struct Snapshot {
    pub sources: Vec<SourceDto>,
    pub candidates: Vec<CandidateDto>,
    pub edges: Vec<EdgeDto>,
    pub fanouts: Vec<FanoutDto>,
    pub branches: Vec<BranchDto>,
    pub runs: Vec<RunDto>,
}

#[derive(Debug, Serialize)]
pub struct SourceDto {
    pub id: i64,
    pub kind: String,
    pub filename: String,
    pub byte_len: i64,
    pub pack_checksum: Option<String>,
    pub idx_pack_checksum: Option<String>,
    pub attached_pack_id: Option<i64>,
    pub status: String,
    pub note: Option<String>,
    /// 删除该源将影响（仍依赖它）的候选 id。
    pub deletion_impact: Vec<i64>,
}

#[derive(Debug, Serialize)]
pub struct CandidateDto {
    pub id: i64,
    pub source_id: i64,
    pub origin: String,
    pub etype: String,
    pub kind: Option<String>,
    pub declared_size: i64,
    pub inflated_size: i64,
    pub pack_offset: Option<i64>,
    pub data_start: Option<i64>,
    pub zlib_consumed: Option<i64>,
    pub claim_oid: Option<String>,
    pub resolved_oid: Option<String>,
    pub resolved_kind: Option<String>,
    pub resolved_size: Option<i64>,
    pub status: String,
    pub chain_depth: Option<i64>,
    pub base_ofs: Option<i64>,
    pub base_ref_oid: Option<String>,
    pub crc_ok: Option<i64>,
    pub parse_error_code: Option<String>,
    pub parse_error: Option<String>,
    pub runtime_error_code: Option<String>,
    pub runtime_error: Option<String>,
    pub blocking_chain: Vec<BlockDto>,
    pub preview: String,
    /// 同一声称 oid 的候选数量（>1 即重复/冲突）。
    pub claim_alternatives: usize,
}

#[derive(Debug, Serialize, serde::Deserialize)]
pub struct BlockDto {
    pub cand: i64,
    pub oid: Option<String>,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct EdgeDto {
    pub from_cand: i64,
    pub to_cand: Option<i64>,
    pub kind: String,
    pub ref_oid: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct FanoutDto {
    pub source_id: i64,
    pub kind: String,
    pub cumulative: Vec<u32>,
}

#[derive(Debug, Serialize)]
pub struct BranchDto {
    pub id: i64,
    pub name: String,
    pub pinned_source_id: Option<i64>,
    pub pinned_cand_id: Option<i64>,
    pub ref_oid: String,
}

#[derive(Debug, Serialize)]
pub struct RunDto {
    pub id: i64,
    pub scope: String,
    pub budget_json: String,
    pub finished: i64,
    pub complete: i64,
}

#[derive(Debug, Serialize)]
pub struct DeltaStepDto {
    pub step: i64,
    pub base_cand: Option<i64>,
    pub base_oid: Option<String>,
    pub declared_base_len: i64,
    pub declared_result_len: i64,
    pub input_len: i64,
    pub output_len: i64,
    pub op_count: i64,
    pub summary: String,
    pub input_ok: i64,
    pub output_ok: i64,
    pub ops: Vec<crate::types::OpRange>,
}

#[derive(Debug, Serialize)]
pub struct CandidateDetail {
    #[serde(flatten)]
    pub candidate: CandidateDto,
    pub steps: Vec<DeltaStepDto>,
    pub header_hex: String,
}

fn collect_sources(tx: &rusqlite::Transaction) -> Vec<SourceDto> {
    let mut out = Vec::new();
    let mut stmt = tx
        .prepare(
            "SELECT id, kind, filename, byte_len, pack_checksum, idx_pack_checksum,
                    attached_pack_id, status, note FROM sources ORDER BY id",
        )
        .unwrap();
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, Option<String>>(4)?,
                r.get::<_, Option<String>>(5)?,
                r.get::<_, Option<i64>>(6)?,
                r.get::<_, String>(7)?,
                r.get::<_, Option<String>>(8)?,
            ))
        })
        .unwrap();
    for row in rows {
        let (id, kind, filename, byte_len, pcs, ipcs, attached, status, note) = row.unwrap();
        let impact: Vec<i64> = tx
            .prepare("SELECT id FROM candidates WHERE source_id=?1 ORDER BY id")
            .unwrap()
            .query_map(params![id], |r| r.get::<_, i64>(0))
            .unwrap()
            .flatten()
            .collect();
        out.push(SourceDto {
            id,
            kind,
            filename,
            byte_len,
            pack_checksum: pcs,
            idx_pack_checksum: ipcs,
            attached_pack_id: attached,
            status,
            note,
            deletion_impact: impact,
        });
    }
    out
}

fn claim_counts(tx: &rusqlite::Transaction) -> std::collections::BTreeMap<String, usize> {
    let mut m = std::collections::BTreeMap::new();
    let mut stmt = tx
        .prepare("SELECT claim_oid, COUNT(*) FROM candidates WHERE claim_oid IS NOT NULL GROUP BY claim_oid")
        .unwrap();
    let rows = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
        .unwrap();
    for (oid, cnt) in rows.flatten() {
        m.insert(oid, cnt as usize);
    }
    m
}

fn collect_candidates(tx: &rusqlite::Transaction) -> Vec<CandidateDto> {
    let counts = claim_counts(tx);
    let mut out = Vec::new();
    let mut stmt = tx
        .prepare(
            "SELECT id, source_id, origin, etype, COALESCE(kind, resolved_kind),
                    declared_size, inflated_size, pack_offset, data_start, zlib_consumed,
                    claim_oid, resolved_oid, resolved_kind, resolved_size, status,
                    chain_depth, base_ofs, base_ref_oid, crc_ok, parse_error_code,
                    parse_error, runtime_error_code, runtime_error,
                    COALESCE(blocking_chain,'[]'),
                    COALESCE(resolved_content, payload)
             FROM candidates ORDER BY source_id, COALESCE(pack_offset,0), id",
        )
        .unwrap();
    let rows = stmt
        .query_map([], |r| {
            Ok(CandidateRow {
                id: r.get(0)?,
                source_id: r.get(1)?,
                origin: r.get(2)?,
                etype: r.get(3)?,
                kind: r.get(4)?,
                declared_size: r.get(5)?,
                inflated_size: r.get(6)?,
                pack_offset: r.get(7)?,
                data_start: r.get(8)?,
                zlib_consumed: r.get(9)?,
                claim_oid: r.get(10)?,
                resolved_oid: r.get(11)?,
                resolved_kind: r.get(12)?,
                resolved_size: r.get(13)?,
                status: r.get(14)?,
                chain_depth: r.get(15)?,
                base_ofs: r.get(16)?,
                base_ref_oid: r.get(17)?,
                crc_ok: r.get(18)?,
                parse_error_code: r.get(19)?,
                parse_error: r.get(20)?,
                runtime_error_code: r.get(21)?,
                runtime_error: r.get(22)?,
                blocking: r.get(23)?,
                content: r.get::<_, Option<Vec<u8>>>(24)?.unwrap_or_default(),
            })
        })
        .unwrap();
    for row in rows {
        let c = row.unwrap();
        let blocking: Vec<BlockDto> =
            serde_json::from_str(&c.blocking).unwrap_or_default();
        let alt = c
            .claim_oid
            .as_ref()
            .map(|o| *counts.get(o).unwrap_or(&1))
            .unwrap_or(1);
        out.push(CandidateDto {
            id: c.id,
            source_id: c.source_id,
            origin: c.origin,
            etype: c.etype.clone(),
            kind: c.kind,
            declared_size: c.declared_size,
            inflated_size: c.inflated_size,
            pack_offset: c.pack_offset,
            data_start: c.data_start,
            zlib_consumed: c.zlib_consumed,
            claim_oid: c.claim_oid,
            resolved_oid: c.resolved_oid,
            resolved_kind: c.resolved_kind,
            resolved_size: c.resolved_size,
            status: c.status,
            chain_depth: c.chain_depth,
            base_ofs: c.base_ofs,
            base_ref_oid: c.base_ref_oid,
            crc_ok: c.crc_ok,
            parse_error_code: c.parse_error_code,
            parse_error: c.parse_error,
            runtime_error_code: c.runtime_error_code,
            runtime_error: c.runtime_error,
            blocking_chain: blocking,
            preview: git::preview(&c.content, 240),
            claim_alternatives: alt,
        });
    }
    out
}

struct CandidateRow {
    id: i64,
    source_id: i64,
    origin: String,
    etype: String,
    kind: Option<String>,
    declared_size: i64,
    inflated_size: i64,
    pack_offset: Option<i64>,
    data_start: Option<i64>,
    zlib_consumed: Option<i64>,
    claim_oid: Option<String>,
    resolved_oid: Option<String>,
    resolved_kind: Option<String>,
    resolved_size: Option<i64>,
    status: String,
    chain_depth: Option<i64>,
    base_ofs: Option<i64>,
    base_ref_oid: Option<String>,
    crc_ok: Option<i64>,
    parse_error_code: Option<String>,
    parse_error: Option<String>,
    runtime_error_code: Option<String>,
    runtime_error: Option<String>,
    blocking: String,
    content: Vec<u8>,
}

fn collect_edges(tx: &rusqlite::Transaction) -> Vec<EdgeDto> {
    tx.prepare("SELECT from_cand, to_cand, kind, ref_oid FROM edges ORDER BY from_cand")
        .unwrap()
        .query_map([], |r| {
            Ok(EdgeDto {
                from_cand: r.get(0)?,
                to_cand: r.get(1)?,
                kind: r.get(2)?,
                ref_oid: r.get(3)?,
            })
        })
        .unwrap()
        .flatten()
        .collect()
}

fn collect_fanouts(tx: &rusqlite::Transaction) -> Vec<FanoutDto> {
    tx.prepare("SELECT source_id, kind, cumulative_json FROM fanout ORDER BY source_id, id")
        .unwrap()
        .query_map([], |r| {
            let json: String = r.get(2)?;
            Ok(FanoutDto {
                source_id: r.get(0)?,
                kind: r.get(1)?,
                cumulative: serde_json::from_str(&json).unwrap_or_default(),
            })
        })
        .unwrap()
        .flatten()
        .collect()
}

fn collect_branches(tx: &rusqlite::Transaction) -> Vec<BranchDto> {
    tx.prepare("SELECT id, name, pinned_source_id, pinned_cand_id, ref_oid FROM branches ORDER BY id")
        .unwrap()
        .query_map([], |r| {
            Ok(BranchDto {
                id: r.get(0)?,
                name: r.get(1)?,
                pinned_source_id: r.get(2)?,
                pinned_cand_id: r.get(3)?,
                ref_oid: r.get(4)?,
            })
        })
        .unwrap()
        .flatten()
        .collect()
}

fn collect_runs(tx: &rusqlite::Transaction) -> Vec<RunDto> {
    tx.prepare("SELECT id, scope, budget_json, finished, complete FROM runs ORDER BY id DESC LIMIT 20")
        .unwrap()
        .query_map([], |r| {
            Ok(RunDto {
                id: r.get(0)?,
                scope: r.get(1)?,
                budget_json: r.get(2)?,
                finished: r.get(3)?,
                complete: r.get(4)?,
            })
        })
        .unwrap()
        .flatten()
        .collect()
}

pub fn build_snapshot(tx: &rusqlite::Transaction) -> Snapshot {
    Snapshot {
        sources: collect_sources(tx),
        candidates: collect_candidates(tx),
        edges: collect_edges(tx),
        fanouts: collect_fanouts(tx),
        branches: collect_branches(tx),
        runs: collect_runs(tx),
    }
}

pub fn candidate_detail(tx: &rusqlite::Transaction, id: i64) -> Option<CandidateDetail> {
    let snap = build_snapshot(tx);
    let candidate = snap.candidates.into_iter().find(|c| c.id == id)?;
    let steps = tx
        .prepare(
            "SELECT step, base_cand, base_oid, declared_base_len, declared_result_len,
                    input_len, output_len, op_count, summary, input_ok, output_ok, ops_json
             FROM delta_steps WHERE cand_id=?1 ORDER BY step",
        )
        .unwrap()
        .query_map(params![id], |r| {
            let ops_json: String = r.get(11)?;
            Ok(DeltaStepDto {
                step: r.get(0)?,
                base_cand: r.get(1)?,
                base_oid: r.get(2)?,
                declared_base_len: r.get(3)?,
                declared_result_len: r.get(4)?,
                input_len: r.get(5)?,
                output_len: r.get(6)?,
                op_count: r.get(7)?,
                summary: r.get(8)?,
                input_ok: r.get(9)?,
                output_ok: r.get(10)?,
                ops: serde_json::from_str(&ops_json).unwrap_or_default(),
            })
        })
        .unwrap()
        .flatten()
        .collect();
    let header_hex: String = tx
        .query_row(
            "SELECT hex(substr(payload,1,32)) FROM candidates WHERE id=?1",
            params![id],
            |r| r.get(0),
        )
        .unwrap_or_default();
    Some(CandidateDetail {
        candidate,
        steps,
        header_hex,
    })
}
