//! loose object 解析：zlib(`<type> <size>\0<body>`)。

use crate::hash::{git_object_id, hex20};
use crate::types::{Evidence, LooseReport, ObjType};
use crate::zlib::{evidence_for, inflate_stream};

pub fn looks_like_loose_path(path: &str) -> bool {
    // 形如 ab/cdef...（2 + 38 hex）。
    let parts: Vec<&str> = path.rsplit('/').take(2).collect();
    if parts.len() != 2 {
        return false;
    }
    let (name, dir) = (parts[0], parts[1]);
    dir.len() == 2 && name.len() == 38 && dir.bytes().all(|b| b.is_ascii_hexdigit()) && name.bytes().all(|b| b.is_ascii_hexdigit())
}

/// 从文件内容解析 loose 对象。`expected_oid` 来自目录名（ab/cdef…），会与
/// 重算的对象 id 比对。
pub fn parse_loose(buf: &[u8], expected_oid: Option<&str>) -> LooseReport {
    let mut ev = Vec::new();
    let inf = match inflate_stream(buf, 0, None) {
        Ok(i) => i,
        Err(e) => {
            let ev = evidence_for(&e, 0);
            let partial = e.partial;
            return LooseReport {
                oid: expected_oid.map(|s| s.to_string()),
                obj_type: ObjType::Bad,
                declared_size: 0,
                inflated_size: partial.len() as u64,
                body: partial,
                evidence: vec![ev],
            };
        }
    };
    let data = inf.data;
    let nul = match data.iter().position(|&b| b == 0) {
        Some(i) => i,
        None => {
            return LooseReport {
                oid: expected_oid.map(|s| s.to_string()),
                obj_type: ObjType::Bad,
                declared_size: 0,
                inflated_size: data.len() as u64,
                body: data,
                evidence: vec![Evidence::new("loose_bad_header", "loose 对象缺少 NUL 头分隔符", None, None)],
            };
        }
    };
    let header = String::from_utf8_lossy(&data[..nul]);
    let mut parts = header.splitn(2, ' ');
    let tname = parts.next().unwrap_or("");
    let size_s = parts.next().unwrap_or("");
    let obj_type = match tname {
        "commit" => ObjType::Commit,
        "tree" => ObjType::Tree,
        "blob" => ObjType::Blob,
        "tag" => ObjType::Tag,
        _ => ObjType::Bad,
    };
    if obj_type == ObjType::Bad {
        ev.push(Evidence::new("loose_bad_type", format!("loose 头类型非法：{tname:?}"), Some(0), Some(nul as u64)));
    }
    let declared: u64 = size_s.parse().unwrap_or(u64::MAX);
    let body = data[nul + 1..].to_vec();
    if declared != body.len() as u64 {
        ev.push(Evidence::new(
            "size_spoof",
            format!("loose 头声明 {declared} 字节，实际 body {} 字节", body.len()),
            Some(0),
            Some(nul as u64),
        ));
    }

    let computed = git_object_id(obj_type, &body);
    if let Some(oid) = computed {
        let hex = hex20(&oid);
        if let Some(exp) = expected_oid {
            if !eq_oid(exp, &hex) {
                ev.push(Evidence::new(
                    "oid_mismatch",
                    format!("loose 路径 oid {exp} 与重算 {hex} 不符，内容可能被替换"),
                    None,
                    None,
                ));
            }
        }
        LooseReport { oid: Some(hex), obj_type, declared_size: declared, inflated_size: body.len() as u64, body, evidence: ev }
    } else {
        LooseReport { oid: expected_oid.map(str::to_string), obj_type, declared_size: declared, inflated_size: body.len() as u64, body, evidence: ev }
    }
}

fn eq_oid(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}
