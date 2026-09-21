// 验收测试:全部自建小 pack,不调用系统 git,核心解析仅使用 microscope 库。
use flate2::{write::ZlibEncoder, Compression};
use microscope::db;
use microscope::engine;
use microscope::gitobj;
use rusqlite::Connection;
use sha1::{Digest, Sha1};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(1);

struct Harness {
    dir: PathBuf,
    conn: Connection,
}

impl Harness {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "microscope_test_{}_{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(dir.join("incoming")).unwrap();
        let conn = db::open(&dir.join("test.db")).unwrap();
        Harness { dir, conn }
    }

    fn import(&self, name: &str, bytes: &[u8]) -> i64 {
        engine::import_bytes(&self.conn, &self.dir, name, bytes).unwrap()
    }

    fn status(&self, oid_or_none_finder: impl Fn(&Connection) -> i64) -> (String, Option<String>) {
        let id = oid_or_none_finder(&self.conn);
        self.conn
            .query_row(
                "SELECT status, error FROM objects WHERE id=?1",
                [id],
                |r| Ok((r.get::<_, String>(0)?, r.get(1)?)),
            )
            .unwrap()
    }

    fn object(&self, id: i64) -> (String, Option<Vec<u8>>, i64) {
        self.conn
            .query_row(
                "SELECT status, content, gen FROM objects WHERE id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap()
    }

    fn by_offset(&self, file_id: i64, off: i64) -> i64 {
        self.conn
            .query_row(
                "SELECT id FROM objects WHERE file_id=?1 AND offset=?2",
                rusqlite::params![file_id, off],
                |r| r.get(0),
            )
            .unwrap()
    }

    fn set_budget(&self, depth: i64, total: i64, ratio: f64) {
        engine::set_budget(&self.conn, depth, total, ratio).unwrap();
    }
}

/* ---------- 自建 Git 格式的构造工具 ---------- */

fn zcompress(data: &[u8]) -> Vec<u8> {
    let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
    use std::io::Write;
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn varint7(mut n: u64) -> Vec<u8> {
    let mut out = vec![(n & 0x7f) as u8];
    n >>= 7;
    while n > 0 {
        out.push((n & 0x7f) as u8 | 0x80);
        n >>= 7;
    }
    out
}

fn obj_header(code: u8, size: u64) -> Vec<u8> {
    let mut size = size;
    let mut first = ((code & 7) << 4) | ((size & 0x0f) as u8);
    size >>= 4;
    if size > 0 {
        first |= 0x80;
    }
    let mut out = vec![first];
    while size > 0 {
        let mut b = (size & 0x7f) as u8;
        size >>= 7;
        if size > 0 {
            b |= 0x80;
        }
        out.push(b);
    }
    out
}

fn ofs_encoding(mut offset: u64) -> Vec<u8> {
    let mut out = vec![(offset & 0x7f) as u8];
    offset >>= 7;
    while offset > 0 {
        offset -= 1;
        out.push(((offset & 0x7f) as u8) | 0x80);
        offset >>= 7;
    }
    out.reverse();
    out
}

struct BuiltPack {
    bytes: Vec<u8>,
    offsets: Vec<i64>,
}

fn build_pack(entries: &[Vec<u8>]) -> BuiltPack {
    let mut out = b"PACK".to_vec();
    out.extend(2u32.to_be_bytes());
    out.extend((entries.len() as u32).to_be_bytes());
    let mut offsets = Vec::new();
    for e in entries {
        offsets.push(out.len() as i64);
        out.extend(e);
    }
    let sum = Sha1::digest(&out);
    out.extend(sum);
    BuiltPack { bytes: out, offsets }
}

fn full_entry(code: u8, content: &[u8]) -> Vec<u8> {
    let mut e = obj_header(code, content.len() as u64);
    e.extend(zcompress(content));
    e
}

fn ref_delta_entry(base_oid: &str, delta: &[u8]) -> Vec<u8> {
    let mut e = obj_header(7, delta.len() as u64);
    e.extend(hex::decode(base_oid).unwrap());
    e.extend(zcompress(delta));
    e
}

fn size_header(n: u64) -> Vec<u8> {
    varint7(n)
}

/// 构造把 base 变成 result 的 delta:复制公共前缀,insert 剩余部分。
fn make_delta(base: &[u8], result: &[u8]) -> Vec<u8> {
    let common = base
        .iter()
        .zip(result.iter())
        .take_while(|(a, b)| a == b)
        .count()
        .min(base.len())
        .min(result.len());
    let mut d = size_header(base.len() as u64);
    d.extend(size_header(result.len() as u64));
    let mut copied = 0usize;
    while copied < common {
        let chunk = (common - copied).min(0xffff);
        let mut cmd = 0x80u8;
        let off = copied as u64;
        let len = chunk as u64;
        for i in 0..4 {
            if (off >> (8 * i)) & 0xff != 0 {
                cmd |= 1 << i;
            }
        }
        for i in 0..3 {
            if (len >> (8 * i)) & 0xff != 0 {
                cmd |= 0x10 << i;
            }
        }
        d.push(cmd);
        for i in 0..4 {
            if (off >> (8 * i)) & 0xff != 0 {
                d.push(((off >> (8 * i)) & 0xff) as u8);
            }
        }
        for i in 0..3 {
            if (len >> (8 * i)) & 0xff != 0 {
                d.push(((len >> (8 * i)) & 0xff) as u8);
            }
        }
        copied += chunk;
    }
    let rest = &result[common..];
    for chunk in rest.chunks(127) {
        d.push(chunk.len() as u8);
        d.extend(chunk);
    }
    d
}

fn idx_v2(entries: &[(String, u32, i64)]) -> Vec<u8> {
    let mut sorted = entries.to_vec();
    sorted.sort();
    let mut out = vec![0xff, 0x74, 0x4f, 0x63];
    out.extend(2u32.to_be_bytes());
    let mut fanout = [0u32; 256];
    for (oid, _, _) in &sorted {
        fanout[usize::from_str_radix(&oid[..2], 16).unwrap()] += 1;
    }
    let mut cum = 0u32;
    for f in fanout.iter_mut() {
        cum += *f;
        *f = cum;
        out.extend(f.to_be_bytes());
    }
    for (oid, _, _) in &sorted {
        out.extend(hex::decode(oid).unwrap());
    }
    for (_, crc, _) in &sorted {
        out.extend(crc.to_be_bytes());
    }
    for (_, _, off) in &sorted {
        out.extend((*off as u32).to_be_bytes());
    }
    out.extend([0u8; 20]);
    let sum = Sha1::digest(&out);
    out.extend(sum);
    out
}

fn entry_crc(pack: &[u8], obj_idx: usize) -> (u32, i64) {
    let info = gitobj::parse_pack(pack).unwrap();
    let o = &info.objects[obj_idx];
    let end = (o.comp_start + o.comp_len) as usize;
    (crc32fast::hash(&pack[o.offset as usize..end]), o.offset as i64)
}

fn loose(otype: &str, content: &[u8]) -> Vec<u8> {
    let mut raw = format!("{otype} {}\0", content.len()).into_bytes();
    raw.extend(content);
    zcompress(&raw)
}

/* ---------------- 测试用例 ---------------- */

#[test]
fn loose_object_roundtrip() {
    let h = Harness::new();
    let content = b"hello loose object";
    let id = h.import("abc123", &loose("blob", content));
    let (st, got, gen) = h.object(id);
    assert_eq!(st, "ok");
    assert_eq!(got.unwrap(), content);
    assert_eq!(gen, 1);
}

#[test]
fn chained_ofs_delta() {
    let h = Harness::new();
    let base = b"hello brave new world";
    let r1 = {
        let mut v = base.to_vec();
        v.extend(b"!!!");
        v
    };
    let r2 = {
        let mut v = r1.clone();
        v.extend(b"??");
        v
    };
    let d1 = make_delta(base, &r1);
    let d2 = make_delta(&r1, &r2);
    let e0 = full_entry(3, base);
    // 先占位算偏移
    let mut probe = b"PACK".to_vec();
    probe.extend(2u32.to_be_bytes());
    probe.extend(3u32.to_be_bytes());
    probe.extend(&e0);
    let off0 = probe.len() as i64 - e0.len() as i64;
    // ofs 距离需要在条目构造前知道,先用 d1 长度估算不行,采用两段拼包:
    let e1_probe = {
        let mut e = obj_header(6, d1.len() as u64);
        e.extend(ofs_encoding(0)); // 距离占位 1 字节(base 在 <128 距离内)
        e
    };
    let off1 = off0 + e0.len() as i64;
    let _ = off1;
    let dist1 = (e0.len()) as u64; // off1 - off0
    assert!(dist1 < 128);
    let e1 = {
        let mut e = obj_header(6, d1.len() as u64);
        e.extend(ofs_encoding(dist1));
        e.extend(zcompress(&d1));
        e
    };
    let _ = e1_probe;
    let dist2 = e1.len() as u64;
    let e2 = {
        let mut e = obj_header(6, d2.len() as u64);
        e.extend(ofs_encoding(dist2));
        e.extend(zcompress(&d2));
        e
    };
    let pack = build_pack(&[e0, e1, e2]);
    let fid = h.import("repo.pack", &pack.bytes);

    let id2 = h.by_offset(fid, pack.offsets[2]);
    let id1 = h.by_offset(fid, pack.offsets[1]);
    let id0 = h.by_offset(fid, pack.offsets[0]);
    let (st2, content, _) = h.object(id2);
    assert_eq!(st2, "ok");
    assert_eq!(content.unwrap(), r2);
    assert_eq!(
        h.object(id0).0,
        "ok"
    );
    assert_eq!(h.object(id1).0, "ok");

    // 期望 oid 用独立计算核对
    let expect_oid = gitobj::git_oid("blob", &r2);
    let got_oid: String = h
        .conn
        .query_row("SELECT oid FROM objects WHERE id=?1", [id2], |r| r.get(0))
        .unwrap();
    assert_eq!(got_oid, expect_oid);

    // 每个 delta 步骤记录 base、指令范围、输入输出长度与校验
    let (in_len, out_len, ok, is_, ie): (i64, i64, i64, i64, i64) = h
        .conn
        .query_row(
            "SELECT in_len, out_len, ok, instr_start, instr_end FROM delta_steps WHERE object_id=?1",
            [id2],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .unwrap();
    assert_eq!(in_len, r1.len() as i64);
    assert_eq!(out_len, r2.len() as i64);
    assert_eq!(ok, 1);
    assert!(ie > is_);
    let base_of: i64 = h
        .conn
        .query_row("SELECT base_object_id FROM links WHERE object_id=?1", [id2], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(base_of, id1);
}

#[test]
fn chained_ref_delta_across_packs() {
    let h = Harness::new();
    let x = b"cross pack base X";
    let y = {
        let mut v = x.to_vec();
        v.extend(b"-Y");
        v
    };
    let z = {
        let mut v = y.clone();
        v.extend(b"-Z");
        v
    };
    let oid_x = gitobj::git_oid("blob", x);
    let oid_y = gitobj::git_oid("blob", &y);

    let pa = build_pack(&[full_entry(3, x)]);
    h.import("a.pack", &pa.bytes);
    let pb = build_pack(&[ref_delta_entry(&oid_x, &make_delta(x, &y))]);
    h.import("b.pack", &pb.bytes);
    let pc = build_pack(&[ref_delta_entry(&oid_y, &make_delta(&y, &z))]);
    let fid_c = h.import("c.pack", &pc.bytes);

    let id = h.by_offset(fid_c, pc.offsets[0]);
    let (st, content, _) = h.object(id);
    assert_eq!(st, "ok", "跨三个 pack 的 ref-delta 链应还原");
    assert_eq!(content.unwrap(), z);
}

#[test]
fn missing_base_then_late_base_only_recomputes_subgraph() {
    let h = Harness::new();
    let unrelated = b"i have nothing to do with deltas";
    let base = b"late arriving base";
    let result = {
        let mut v = base.to_vec();
        v.extend(b"!!");
        v
    };
    let oid_base = gitobj::git_oid("blob", base);

    let p1 = build_pack(&[
        full_entry(3, unrelated),
        ref_delta_entry(&oid_base, &make_delta(base, &result)),
    ]);
    let fid1 = h.import("first.pack", &p1.bytes);
    let id_unrel = h.by_offset(fid1, p1.offsets[0]);
    let id_delta = h.by_offset(fid1, p1.offsets[1]);

    let (st, err): (String, Option<String>) = h
        .conn
        .query_row("SELECT status, error FROM objects WHERE id=?1", [id_delta], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(st, "blocked");
    assert!(err.unwrap().contains("缺少外部 base"));
    let dep: String = h
        .conn
        .query_row("SELECT dep FROM blocking WHERE object_id=?1", [id_delta], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(dep, format!("oid:{oid_base}"));
    let gen_unrel_before: i64 = h
        .conn
        .query_row("SELECT gen FROM objects WHERE id=?1", [id_unrel], |r| r.get(0))
        .unwrap();

    // 补入 base:只重算受影响的依赖子图
    let p2 = build_pack(&[full_entry(3, base)]);
    h.import("second.pack", &p2.bytes);

    let (st2, content, _) = h.object(id_delta);
    assert_eq!(st2, "ok");
    assert_eq!(content.unwrap(), result);
    let gen_unrel_after: i64 = h
        .conn
        .query_row("SELECT gen FROM objects WHERE id=?1", [id_unrel], |r| r.get(0))
        .unwrap();
    assert_eq!(
        gen_unrel_before, gen_unrel_after,
        "无关对象不得被重新计算"
    );
}

#[test]
fn ref_delta_cycle_is_detected_and_isolated() {
    let h = Harness::new();
    let x = b"cycle result X";
    let y = b"cycle result YYY";
    let oid_x = gitobj::git_oid("blob", x);
    let oid_y = gitobj::git_oid("blob", y);

    // pack1: delta 结果为 X,声称 base 是 oid(Y);idx 声明该条目 oid(X)
    let p1 = build_pack(&[ref_delta_entry(&oid_y, &make_delta(y, x))]);
    let f1 = h.import("cyc1.pack", &p1.bytes);
    let i1 = idx_v2(&[(oid_x.clone(), 0xdeadbeef, p1.offsets[0])]);
    h.import("cyc1.idx", &i1);

    let p2 = build_pack(&[ref_delta_entry(&oid_x, &make_delta(x, y))]);
    h.import("cyc2.pack", &p2.bytes);
    let i2 = idx_v2(&[(oid_y.clone(), 0xdeadbeef, p2.offsets[0])]);
    h.import("cyc2.idx", &i2);

    let id1 = h.by_offset(f1, p1.offsets[0]);
    let (st1, err1) = h.status(move |_| id1);
    assert_eq!(st1, "error");
    assert!(err1.unwrap().contains("delta 环"));

    // 环里另一个对象同样隔离为 error,且没有内容泄漏
    let other: (String, Option<Vec<u8>>) = h
        .conn
        .query_row(
            "SELECT status, content FROM objects o JOIN files f ON f.id=o.file_id
             WHERE f.name='cyc2.pack'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(other.0, "error");
    assert!(other.1.is_none());
}

#[test]
fn bad_crc_reported_as_evidence() {
    let h = Harness::new();
    let content = b"crc check target";
    let pack = build_pack(&[full_entry(3, content)]);
    h.import("crc.pack", &pack.bytes);
    let (crc, off) = entry_crc(&pack.bytes, 0);
    let idx = idx_v2(&[(gitobj::git_oid("blob", content), crc ^ 0xffff_ffff, off)]);
    h.import("crc.idx", &idx);

    let bad: i64 = h
        .conn
        .query_row(
            "SELECT COUNT(*) FROM evidence WHERE level='error' AND message LIKE '%错误 CRC%'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(bad >= 1, "应记录错误 CRC 证据");

    // fanout 也应留痕
    let fan: i64 = h
        .conn
        .query_row(
            "SELECT COUNT(*) FROM evidence WHERE message LIKE '%fanout%'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(fan >= 1);
}

#[test]
fn spoofed_size_is_error_but_neighbors_keep_analyzing() {
    let h = Harness::new();
    let good = b"i am fine";
    let evil_content = b"small";
    // 头部伪造大小为 1000,zlib 流只有 5 字节内容
    let mut evil = obj_header(3, 1000);
    evil.extend(zcompress(evil_content));
    let pack = build_pack(&[full_entry(3, good), evil]);
    let fid = h.import("spoof.pack", &pack.bytes);

    let id_good = h.by_offset(fid, pack.offsets[0]);
    let id_evil = h.by_offset(fid, pack.offsets[1]);
    assert_eq!(h.object(id_good).0, "ok");
    let (st, err) = h.status(move |_| id_evil);
    assert_eq!(st, "error");
    assert!(err.unwrap().contains("大小欺骗"));
}

#[test]
fn ofs_distance_out_of_bounds() {
    let h = Harness::new();
    let base = b"base for oob test with some bytes";
    let delta = make_delta(base, b"whatever");
    let mut evil = obj_header(6, delta.len() as u64);
    evil.extend(ofs_encoding(999_999));
    evil.extend(zcompress(&delta));
    let pack = build_pack(&[full_entry(3, base), evil]);
    let fid = h.import("oob.pack", &pack.bytes);
    let id_evil = h.by_offset(fid, pack.offsets[1]);
    let (st, err) = h.status(move |_| id_evil);
    assert_eq!(st, "error");
    assert!(err.unwrap().contains("ofs 距离越界"));
    // 同 pack 的正常对象不受影响
    let id_base = h.by_offset(fid, pack.offsets[0]);
    assert_eq!(h.object(id_base).0, "ok");
}

#[test]
fn duplicate_oid_candidates_order_independent_of_import_order() {
    let h = Harness::new();
    let shared = b"same blob appears in two packs";
    // 加各自不同的哨兵对象,避免两个 pack 内容完全相同被去重
    let pa = build_pack(&[full_entry(3, shared), full_entry(3, b"sentinel A")]);
    let pb = build_pack(&[full_entry(3, shared), full_entry(3, b"sentinel B")]);
    let da = gitobj::digest_hex(&pa.bytes);
    let dbg = gitobj::digest_hex(&pb.bytes);
    // 故意先导入摘要较大的那个
    let (first, second, first_name, second_name) = if da < dbg {
        (&pb, &pa, "dup_b.pack", "dup_a.pack")
    } else {
        (&pa, &pb, "dup_a.pack", "dup_b.pack")
    };
    h.import(first_name, &first.bytes);
    h.import(second_name, &second.bytes);

    let oid = gitobj::git_oid("blob", shared);
    let conflicts = engine::conflicting_oids(&h.conn).unwrap();
    assert!(conflicts.contains(&oid));

    // 候选按源摘要排序,与导入顺序无关:第一位应是摘要最小的文件
    let first_cand_file: String = h
        .conn
        .query_row(
            "SELECT f.digest FROM objects o JOIN files f ON f.id=o.file_id
             WHERE o.oid=?1 AND o.status='ok' ORDER BY f.digest, o.offset, o.id LIMIT 1",
            [&oid],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(first_cand_file, da.clone().min(dbg.clone()));

    // 引用该 oid 的 ref-delta 自动选用排序第一的候选
    let result = b"same blob appears in two packs!!";
    let pc = build_pack(&[ref_delta_entry(&oid, &make_delta(shared, result))]);
    let fidc = h.import("dup_c.pack", &pc.bytes);
    let idc = h.by_offset(fidc, pc.offsets[0]);
    assert_eq!(h.object(idc).0, "ok");
    let chosen_file: String = h
        .conn
        .query_row(
            "SELECT f.digest FROM links l JOIN objects o ON o.id=l.base_object_id
             JOIN files f ON f.id=o.file_id WHERE l.object_id=?1",
            [idc],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(chosen_file, da.min(dbg));
}

#[test]
fn budget_pause_and_resume_never_emits_partial_object() {
    let h = Harness::new();
    h.set_budget(64, 8, 1000.0); // 总展开字节只有 8
    let base = b"twenty bytes long!!"; // 19 字节,超预算
    assert_eq!(base.len(), 19);
    let pack = build_pack(&[full_entry(3, base)]);
    let fid = h.import("tight.pack", &pack.bytes);
    let id = h.by_offset(fid, pack.offsets[0]);

    let (st, content, oid): (String, Option<Vec<u8>>, Option<String>) = h
        .conn
        .query_row(
            "SELECT status, content, oid FROM objects WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(st, "paused");
    assert!(content.is_none(), "暂停对象不得缓存部分内容");
    assert!(oid.is_none());

    // 放宽预算并恢复:可重试的中间状态 -> 完整对象
    h.set_budget(64, 64 * 1024 * 1024, 1000.0);
    engine::resume(&h.conn, &h.dir).unwrap();
    let (st2, content2, _) = h.object(id);
    assert_eq!(st2, "ok");
    assert_eq!(content2.unwrap(), base);
}

#[test]
fn depth_budget_pauses_delta_chain() {
    let h = Harness::new();
    h.set_budget(0, 64 * 1024 * 1024, 1000.0); // 不允许任何 delta 层
    let base = b"depth base";
    let r1 = {
        let mut v = base.to_vec();
        v.push(b'!');
        v
    };
    let e0 = full_entry(3, base);
    let dist1 = e0.len() as u64;
    let e1 = {
        let d = make_delta(base, &r1);
        let mut e = obj_header(6, d.len() as u64);
        e.extend(ofs_encoding(dist1));
        e.extend(zcompress(&d));
        e
    };
    let pack = build_pack(&[e0, e1]);
    let fid = h.import("depth.pack", &pack.bytes);
    let id1 = h.by_offset(fid, pack.offsets[1]);
    let (st, _) = h.status(move |_| id1);
    assert_eq!(st, "paused");

    h.set_budget(5, 64 * 1024 * 1024, 1000.0);
    engine::resume(&h.conn, &h.dir).unwrap();
    assert_eq!(h.object(id1).0, "ok");
}

#[test]
fn idx_pack_mismatch_is_evidence() {
    let h = Harness::new();
    let pack = build_pack(&[full_entry(3, b"mismatch target data")]);
    h.import("mm.pack", &pack.bytes);
    let oid = "0123456789abcdef0123456789abcdef01234567";
    let idx = idx_v2(&[(oid.to_string(), 0x11223344, 9999)]);
    h.import("mm.idx", &idx);
    let n: i64 = h
        .conn
        .query_row(
            "SELECT COUNT(*) FROM evidence WHERE level='error' AND message LIKE '%不配套%'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(n >= 1);
}

#[test]
fn pin_conflict_source_rebuilds_branch() {
    let h = Harness::new();
    let shared = b"branch base content";
    let pa = build_pack(&[full_entry(3, shared), full_entry(3, b"sentinel A2")]);
    let pb = build_pack(&[full_entry(3, shared), full_entry(3, b"sentinel B2")]);
    let da = gitobj::digest_hex(&pa.bytes);
    let dbg = gitobj::digest_hex(&pb.bytes);
    let (small_pack, small_name, big_name) = if da < dbg {
        (&pa, "ba.pack", "bb.pack")
    } else {
        (&pb, "bb.pack", "ba.pack")
    };
    // 先导入摘要较大的 pack,验证默认候选与导入顺序无关
    let big_bytes: &[u8] = if da < dbg { &pb.bytes } else { &pa.bytes };
    h.import(big_name, big_bytes);
    h.import(small_name, &small_pack.bytes);
    let oid = gitobj::git_oid("blob", shared);

    let result = b"branch base content++";
    let pc = build_pack(&[ref_delta_entry(&oid, &make_delta(shared, result))]);
    let fidc = h.import("bc.pack", &pc.bytes);
    let idc = h.by_offset(fidc, pc.offsets[0]);
    let default_base: i64 = h
        .conn
        .query_row("SELECT base_object_id FROM links WHERE object_id=?1", [idc], |r| {
            r.get(0)
        })
        .unwrap();

    // 固定到另一个候选
    let other: i64 = h
        .conn
        .query_row(
            "SELECT o.id FROM objects o JOIN files f ON f.id=o.file_id
             WHERE o.oid=?1 AND o.status='ok' AND o.id<>?2 ORDER BY f.digest DESC LIMIT 1",
            rusqlite::params![oid, default_base],
            |r| r.get(0),
        )
        .unwrap();
    engine::pin_oid(&h.conn, &h.dir, &oid, Some(other)).unwrap();
    let new_base: i64 = h
        .conn
        .query_row("SELECT base_object_id FROM links WHERE object_id=?1", [idc], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(new_base, other);
    assert_eq!(h.object(idc).0, "ok");

    // 取消固定回到默认排序候选
    engine::pin_oid(&h.conn, &h.dir, &oid, None).unwrap();
    let back: i64 = h
        .conn
        .query_row("SELECT base_object_id FROM links WHERE object_id=?1", [idc], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(back, default_base);
}

#[test]
fn deleting_source_file_invalidates_dependents() {
    let h = Harness::new();
    let base = b"content that will lose its base";
    let result = b"content that will lose its base!!";
    let oid = gitobj::git_oid("blob", base);
    let pbase = build_pack(&[full_entry(3, base)]);
    let fid_base = h.import("keep.pack", &pbase.bytes);
    let pdelta = build_pack(&[ref_delta_entry(&oid, &make_delta(base, result))]);
    let fid_delta = h.import("drop.pack", &pdelta.bytes);
    let id_delta = h.by_offset(fid_delta, pdelta.offsets[0]);
    assert_eq!(h.object(id_delta).0, "ok");

    // 删除 base 源文件前应能列出依赖它的对象
    let deps = engine::dependents_of_file(&h.conn, fid_base).unwrap();
    assert!(deps.contains(&id_delta));

    engine::delete_file(&h.conn, &h.dir, fid_base).unwrap();
    let (st, _) = h.status(move |_| id_delta);
    assert_eq!(st, "blocked");

    // 重新导入 base,局部重算恢复
    let pbase2 = build_pack(&[full_entry(3, base)]);
    h.import("keep2.pack", &pbase2.bytes);
    assert_eq!(h.object(id_delta).0, "ok");
}
