//! Git 对象编码原语：类型、尺寸编码、对象 id、受预算保护的 zlib 解压。

use miniz_oxide::inflate::core::{
    create_inflate_state, inflate, DecompressorOxide, TINFLStatus,
};
use sha1::{Digest, Sha1};

/// Git 内部对象类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitType {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
}

impl GitType {
    pub fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            1 => GitType::Commit,
            2 => GitType::Tree,
            3 => GitType::Blob,
            4 => GitType::Tag,
            6 => GitType::OfsDelta,
            7 => GitType::RefDelta,
            _ => return None,
        })
    }

    pub fn is_delta(self) -> bool {
        matches!(self, GitType::OfsDelta | GitType::RefDelta)
    }

    pub fn name(self) -> &'static str {
        match self {
            GitType::Commit => "commit",
            GitType::Tree => "tree",
            GitType::Blob => "blob",
            GitType::Tag => "tag",
            GitType::OfsDelta => "ofs-delta",
            GitType::RefDelta => "ref-delta",
        }
    }
}

/// 非 delta 类型的名称字符串（`"blob"` 等）。
pub fn type_name(code: u8) -> Option<&'static str> {
    Some(match code {
        1 => "commit",
        2 => "tree",
        3 => "blob",
        4 => "tag",
        _ => return None,
    })
}

/// pack entry 头：3 位类型 + varint 尺寸（首字节低 4 位 + 后续 7 位）。
/// 返回 `(type_code, size, header_len)`。
pub fn parse_entry_header(buf: &[u8]) -> Result<(u8, u64, usize), String> {
    if buf.is_empty() {
        return Err("entry header: 缓冲区为空".into());
    }
    let first = buf[0];
    let type_code = (first >> 4) & 0b111;
    let mut size = u64::from(first & 0x0f);
    let mut shift = 4;
    let mut pos = 1;
    let mut cur = first;
    while cur & 0x80 != 0 {
        if pos >= buf.len() {
            return Err("entry header: 尺寸编码被截断".into());
        }
        cur = buf[pos];
        size |= u64::from(cur & 0x7f) << shift;
        shift += 7;
        pos += 1;
        if pos > 10 {
            return Err("entry header: 尺寸编码过长".into());
        }
    }
    Ok((type_code, size, pos))
}

/// ofs-delta 负偏移的变长编码。返回 `(negative_offset, byte_len)`。
///
/// Git 规则（`get_delta_base_size`）：首字节为 c；结果初始 c&127；
/// 每读一个高位为 1 的字节 c，先 `+1` 再左移 7，然后并入 c&127。
pub fn parse_ofs_delta(buf: &[u8]) -> Result<(u64, usize), String> {
    if buf.is_empty() {
        return Err("ofs-delta: 缓冲区为空".into());
    }
    let mut pos = 0;
    let mut c = buf[0];
    let mut offset = u64::from(c & 0x7f);
    pos += 1;
    while c & 0x80 != 0 {
        if pos >= buf.len() {
            return Err("ofs-delta: 偏移编码被截断".into());
        }
        c = buf[pos];
        pos += 1;
        offset = offset
            .checked_add(1)
            .and_then(|v| v.checked_shl(7))
            .ok_or_else(|| "ofs-delta: 偏移溢出".to_string())?;
        offset |= u64::from(c & 0x7f);
    }
    Ok((offset, pos))
}

/// 计算 Git 对象 id：`sha1("<type> <len>\0<content>")`。
pub fn object_id(type_code: u8, content: &[u8]) -> Result<[u8; 20], String> {
    let name = type_name(type_code).ok_or_else(|| format!("未知对象类型 code={type_code}"))?;
    let mut hasher = Sha1::new();
    hasher.update(name.as_bytes());
    hasher.update(b" ");
    hasher.update(content.len().to_string().as_bytes());
    hasher.update([0u8]);
    hasher.update(content);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hasher.finalize());
    Ok(out)
}

/// 流式 zlib 解压结果。
pub struct Inflated {
    pub data: Vec<u8>,
    /// 压缩流消耗的压缩字节数（zlib 边界）。
    pub consumed: usize,
    /// 声明尺寸与实际解压尺寸是否一致。
    pub size_ok: bool,
    /// 声明尺寸；loose 对象没有声明，记录实际尺寸。
    pub declared: u64,
    /// 是否触碰输出上限（疑似大小欺骗 / zip bomb）。
    pub cap_hit: bool,
}

/// 受输出上限保护地解压一个 zlib 流。
///
/// - `declared`：头中声明的未压缩尺寸，用于检测“解压到一半才发现大小欺骗”。
/// - `hard_cap`：绝对输出上限（`declared + 1` 或全局限额）。命中即 `cap_hit`。
///
/// 用 miniz_oxide 流式接口逐块喂入，精确记录压缩字节消耗，避免一次性分配。
pub fn inflate_limited(
    input: &[u8],
    declared: Option<u64>,
    hard_cap: usize,
) -> Result<Inflated, String> {
    let mut decomp = DecompressorOxide::new_with_flags(true, false);
    let mut state: Box<miniz_oxide::inflate::core::InflateState> = create_inflate_state();
    let mut out = Vec::new();
    let mut in_pos = 0usize;
    let mut finished = false;

    loop {
        let chunk = &input[in_pos..];
        if chunk.is_empty() && !finished {
            return Err("zlib: 压缩流被截断（输入耗尽）".into());
        }
        let mut tmp = [0u8; 64 * 1024];
        let (status, in_consumed, out_consumed) =
            inflate(&mut state, chunk, &mut tmp, TINFLStatus::NeedsMoreInput);
        in_pos += in_consumed;

        if out.len() + out_consumed > hard_cap {
            return Ok(Inflated {
                data: out,
                consumed: in_pos,
                size_ok: false,
                declared: declared.unwrap_or(u64::MAX),
                cap_hit: true,
            });
        }
        out.extend_from_slice(&tmp[..out_consumed]);

        match status {
            TINFLStatus::Done => {
                finished = true;
                break;
            }
            TINFLStatus::NeedsMoreInput => continue,
            TINFLStatus::FailedCannotMakeProgress | TINFLStatus::BadParam => {
                return Err("zlib: 数据流损坏".into());
            }
            other => return Err(format!("zlib: 解压异常状态 {:?}", other)),
        }
    }

    // Done 时 in_pos 已包含 adler32 尾；确认为合法 zlib 边界。
    if in_pos > input.len() {
        return Err("zlib: 消耗字节越界".into());
    }
    let actual = out.len() as u64;
    let (decl, size_ok) = match declared {
        Some(d) => (d, d == actual),
        None => (actual, true),
    };
    Ok(Inflated {
        data: out,
        consumed: in_pos,
        size_ok,
        declared: decl,
        cap_hit: false,
    })
}

/// 宽松对象内容摘要：可打印前缀 + 十六进制预览。
pub fn preview(content: &[u8], limit: usize) -> String {
    let head: Vec<u8> = content.iter().take(limit).copied().collect();
    let text = String::from_utf8_lossy(&head);
    text.chars().take(limit).map(|c| if c.is_control() { '·' } else { c }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_header_roundtrip() {
        // type=3(blob), size=1440000，小端 7 位分组
        let mut bytes = vec![];
        let mut size = 1440000u64;
        let mut first = ((3u8) << 4) | ((size as u8) & 0x0f);
        size >>= 4;
        if size > 0 {
            first |= 0x80;
        }
        bytes.push(first);
        while size > 0 {
            let mut b = (size as u8) & 0x7f;
            size >>= 7;
            if size > 0 {
                b |= 0x80;
            }
            bytes.push(b);
        }
        let (code, parsed, len) = parse_entry_header(&bytes).unwrap();
        assert_eq!(code, 3);
        assert_eq!(parsed, 1440000);
        assert_eq!(len, bytes.len());
    }

    #[test]
    fn ofs_encoding_git_values() {
        // Git 文档常见示例：base = 128, encoded [0x81, 0x00]
        let (off, len) = parse_ofs_delta(&[0x81, 0x00]).unwrap();
        assert_eq!(off, 128);
        assert_eq!(len, 2);
        let (off2, l2) = parse_ofs_delta(&[0x7f]).unwrap();
        assert_eq!(off2, 127);
        assert_eq!(l2, 1);
    }

    #[test]
    fn blob_id_known_value() {
        // 空 blob 的 git oid：e69de29b...
        let id = object_id(3, b"").unwrap();
        assert_eq!(hex::encode(id), "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391");
    }

    #[test]
    fn inflate_detects_size_lie() {
        let data = b"hello world, this is a real payload".to_vec();
        let compressed =
            miniz_oxide::deflate::compress_to_vec_zlib(&data, 6);
        // 声明尺寸远小于实际，cap = declared+1
        let r = inflate_limited(&compressed, Some(5), 6).unwrap();
        assert!(r.cap_hit);
        let r2 = inflate_limited(&compressed, Some(data.len() as u64), data.len()).unwrap();
        assert!(r2.size_ok);
        assert_eq!(r2.data, data);
    }
}
