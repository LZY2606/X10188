use sha1::{Digest, Sha1};

use super::types::GitType;

/// 计算 Git 对象 id：sha1("<type> <len>\0<content>")。
pub fn hash_object(kind: GitType, content: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(kind.name().as_bytes());
    h.update(b" ");
    h.update(content.len().to_string().as_bytes());
    h.update(b"\0");
    h.update(content);
    let out = h.finalize();
    let mut oid = [0u8; 20];
    oid.copy_from_slice(&out);
    oid
}

/// 解析 loose object 解压后的 `type size\0content`。
pub fn parse_loose_payload(data: &[u8]) -> Option<(GitType, Vec<u8>)> {
    let nul = data.iter().position(|b| *b == 0)?;
    let header = std::str::from_utf8(&data[..nul]).ok()?;
    let (name, len_str) = header.split_once(' ')?;
    let kind = GitType::from_name(name)?;
    let len: usize = len_str.parse().ok()?;
    let content = data[nul + 1..].to_vec();
    if len != content.len() {
        return None;
    }
    Some((kind, content))
}

/// 对内容做文本/十六进制预览，供页面展示。
pub fn preview(content: &[u8], limit: usize) -> String {
    let mut s = String::new();
    for &b in content.iter().take(limit) {
        if b == b'\n' || b == b'\t' || (0x20..=0x7e).contains(&b) {
            s.push(b as char);
        } else {
            s.push_str(&format!("\\x{:02x}", b));
        }
    }
    if content.len() > limit {
        s.push('…');
    }
    s
}
