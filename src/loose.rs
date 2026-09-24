//! loose object 解析：目录名前 2 位 hex + 文件名后 38 位 hex，zlib 内容。

use crate::gitobj::unwrap_object;
use crate::oid::{ObjType, Oid};
use crate::zlib::inflate_slice;

const LOOSE_INFLATE_LIMIT: usize = 1 << 30;

pub struct LooseParsed {
    pub file_name: String,
    /// 由路径推得的对象 id。
    pub claimed_oid: Oid,
    pub obj_type: Option<ObjType>,
    pub content: Vec<u8>,
    /// 对解压内容重新计算的 object id。
    pub computed_oid: Option<Oid>,
    pub ok: bool,
    pub error: Option<String>,
}

/// 解析 loose 对象字节。`path_oid` 是根据文件路径推断的 oid。
pub fn parse_loose(file_name: &str, path_oid: Oid, bytes: &[u8]) -> LooseParsed {
    let mut lp = LooseParsed {
        file_name: file_name.to_string(),
        claimed_oid: path_oid,
        obj_type: None,
        content: Vec::new(),
        computed_oid: None,
        ok: false,
        error: None,
    };
    let inf = match inflate_slice(bytes, 0, LOOSE_INFLATE_LIMIT) {
        Ok(v) => v,
        Err(e) => {
            lp.error = Some(format!("loose zlib 解压失败: {e}"));
            return lp;
        }
    };
    if inf.consumed != bytes.len() {
        lp.error = Some(format!(
            "loose zlib 流提前结束：消费 {} 字节，文件 {} 字节（尾部垃圾 / 截断）",
            inf.consumed,
            bytes.len()
        ));
        // 仍继续校验已解出的完整对象会违反“不当完整”，直接返回错误隔离。
        return lp;
    }
    match unwrap_object(&inf.data) {
        Ok((ty, body)) => {
            let oid = Oid(crate::gitobj::hash_object(ty, &body));
            lp.obj_type = Some(ty);
            lp.content = body;
            lp.computed_oid = Some(oid);
            if oid != path_oid {
                lp.error = Some(format!(
                    "loose object id 不匹配：路径 {}，内容计算 {}",
                    path_oid.short(),
                    oid.short()
                ));
            } else {
                lp.ok = true;
            }
        }
        Err(e) => lp.error = Some(e),
    }
    lp
}

/// 由 "xx/yyyy...38hex" 形式的相对路径推断 oid。
pub fn oid_from_relpath(rel: &str) -> Option<Oid> {
    let p = rel.replace('\\', "/");
    let (dir, name) = p.rsplit_once('/')?;
    let dir = dir.rsplit('/').next().unwrap_or(dir);
    if dir.len() != 2 || name.len() != 38 {
        return None;
    }
    Oid::from_hex(&format!("{dir}{name}"))
}
