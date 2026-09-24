use crate::git::oid_hex;
use crate::pack::HARD_CAP;
use crate::zutil::decompress_bounded;

#[derive(Default, Clone, Debug)]
pub struct LooseInfo {
    pub oid: String,
    pub otype: String,
    pub size: u64,
    pub content: Vec<u8>,
    pub error: Option<String>,
}

pub fn parse_loose(buf: &[u8]) -> LooseInfo {
    let mut info = LooseInfo::default();
    let raw = match decompress_bounded(buf, HARD_CAP) {
        Ok((v, _)) => v,
        Err(msg) => {
            info.error = Some(msg);
            return info;
        }
    };
    let nul = match raw.iter().position(|b| *b == 0) {
        Some(p) => p,
        None => {
            info.error = Some("loose 对象头缺少 NUL".into());
            return info;
        }
    };
    let header = match std::str::from_utf8(&raw[..nul]) {
        Ok(s) => s,
        Err(_) => {
            info.error = Some("loose 对象头不是合法 UTF-8".into());
            return info;
        }
    };
    let (otype, size_str) = match header.split_once(' ') {
        Some(v) => v,
        None => {
            info.error = Some(format!("loose 对象头格式错误: {header:?}"));
            return info;
        }
    };
    let size: u64 = match size_str.parse() {
        Ok(v) => v,
        Err(_) => {
            info.error = Some(format!("loose 对象大小不是数字: {size_str:?}"));
            return info;
        }
    };
    let content = raw[nul + 1..].to_vec();
    if content.len() as u64 != size {
        info.error = Some(format!(
            "loose 声明大小 {size} 与实际内容长度 {} 不一致",
            content.len()
        ));
    }
    if !matches!(otype, "commit" | "tree" | "blob" | "tag") {
        let e = format!("loose 对象类型非法: {otype}");
        info.error = Some(info.error.map(|x| format!("{x}; {e}")).unwrap_or(e));
    }
    info.oid = oid_hex(otype, &content);
    info.otype = otype.to_string();
    info.size = size;
    info.content = content;
    info
}
