//! Git object primitives: object ids, zlib boundary detection, delta application.
//! No system git is invoked anywhere; everything is parsed in pure Rust.

use flate2::{Decompress, FlushDecompress, Status};
use sha1::{Digest, Sha1};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ObjType {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
}

impl ObjType {
    pub fn from_pack_code(code: u8) -> Option<ObjType> {
        match code {
            1 => Some(ObjType::Commit),
            2 => Some(ObjType::Tree),
            3 => Some(ObjType::Blob),
            4 => Some(ObjType::Tag),
            6 => Some(ObjType::OfsDelta),
            7 => Some(ObjType::RefDelta),
            _ => None,
        }
    }
    pub fn pack_code(self) -> u8 {
        match self {
            ObjType::Commit => 1,
            ObjType::Tree => 2,
            ObjType::Blob => 3,
            ObjType::Tag => 4,
            ObjType::OfsDelta => 6,
            ObjType::RefDelta => 7,
        }
    }
    /// Name used in the loose-object / object-id header. Delta types have none.
    pub fn header_name(self) -> Option<&'static str> {
        match self {
            ObjType::Commit => Some("commit"),
            ObjType::Tree => Some("tree"),
            ObjType::Blob => Some("blob"),
            ObjType::Tag => Some("tag"),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            ObjType::Commit => "commit",
            ObjType::Tree => "tree",
            ObjType::Blob => "blob",
            ObjType::Tag => "tag",
            ObjType::OfsDelta => "ofs_delta",
            ObjType::RefDelta => "ref_delta",
        }
    }
    pub fn parse(s: &str) -> Option<ObjType> {
        Some(match s {
            "commit" => ObjType::Commit,
            "tree" => ObjType::Tree,
            "blob" => ObjType::Blob,
            "tag" => ObjType::Tag,
            "ofs_delta" => ObjType::OfsDelta,
            "ref_delta" => ObjType::RefDelta,
            _ => return None,
        })
    }
    pub fn is_delta(self) -> bool {
        matches!(self, ObjType::OfsDelta | ObjType::RefDelta)
    }
}

/// Compute the Git object id (SHA-1 of "<type> <len>\0" + content).
pub fn object_id(obj_type: ObjType, content: &[u8]) -> String {
    let name = obj_type.header_name().expect("delta types have no object id");
    let mut h = Sha1::new();
    h.update(format!("{} {}\0", name, content.len()).as_bytes());
    h.update(content);
    hex_encode(&h.finalize())
}

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok())
        .collect()
}

/// Result of a bounded zlib inflation.
pub struct InflateResult {
    pub out: Vec<u8>,
    /// Number of input bytes consumed by the zlib stream (the zlib boundary).
    pub consumed: usize,
    /// True when the stream ended cleanly (Z_STREAM_END).
    pub stream_end: bool,
}

/// Inflate a zlib stream starting at `input`, stopping at the stream end and
/// reporting exactly how many input bytes the stream occupied. `max_out` caps
/// the output; exceeding it is an error (size-spoof / bomb protection) and no
/// partial output is returned.
pub fn zlib_inflate_bounded(input: &[u8], max_out: u64) -> Result<InflateResult, String> {
    let mut d = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    let mut offset = 0usize;
    loop {
        let before_in = d.total_in();
        let before_out = d.total_out();
        let status = d
            .decompress(&input[offset..], &mut chunk, FlushDecompress::None)
            .map_err(|e| format!("zlib 解压失败: {e}"))?;
        let produced = (d.total_out() - before_out) as usize;
        out.extend_from_slice(&chunk[..produced]);
        offset += (d.total_in() - before_in) as usize;
        if out.len() as u64 > max_out {
            return Err(format!(
                "解压输出超过声明上限 ({} > {}): 疑似大小欺骗",
                out.len(),
                max_out
            ));
        }
        match status {
            Status::StreamEnd => {
                return Ok(InflateResult {
                    out,
                    consumed: offset,
                    stream_end: true,
                })
            }
            Status::Ok | Status::BufError => {
                let made_progress = d.total_in() > before_in || d.total_out() > before_out;
                if offset >= input.len() || !made_progress {
                    // Truncated stream: ran out of input before Z_STREAM_END.
                    return Err(format!(
                        "zlib 流在第 {} 字节处截断, 未到达流尾 (已解压 {} 字节)",
                        offset,
                        out.len()
                    ));
                }
            }
        }
    }
}

/// One recorded delta application step (evidence).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeltaStep {
    /// Human readable base reference: "ofs:<offset>" or "ref:<oid>".
    pub base: String,
    /// Byte range of the instruction stream inside the delta data [start, end).
    pub instr_range: (usize, usize),
    pub input_len: usize,
    pub output_len: usize,
    pub declared_base_len: usize,
    pub declared_target_len: usize,
    pub ok: bool,
    pub checks: Vec<String>,
}

/// Parse a git delta and apply it to `base`, recording evidence.
/// Returns (output, step evidence) or an error; on error the evidence is still
/// returned inside `Err((message, step))` so callers can store it.
pub fn apply_delta(base: &[u8], delta: &[u8], base_ref: &str) -> Result<(Vec<u8>, DeltaStep), (String, DeltaStep)> {
    let mut pos = 0usize;
    let mk_step = |pos: usize, delta: &[u8], base_len, out_len, ok, checks| DeltaStep {
        base: base_ref.to_string(),
        instr_range: (pos, delta.len()),
        input_len: base_len,
        output_len: out_len,
        declared_base_len: 0,
        declared_target_len: 0,
        ok,
        checks,
    };
    let (declared_base, n1) = read_varint(delta, pos)
        .ok_or_else(|| ("delta 缺少 base 长度 varint".to_string(), mk_step(0, delta, 0, 0, false, vec![])))?;
    pos += n1;
    let (declared_target, n2) = read_varint(delta, pos)
        .ok_or_else(|| ("delta 缺少 target 长度 varint".to_string(), mk_step(pos, delta, 0, 0, false, vec![])))?;
    pos += n2;

    let mut checks = Vec::new();
    let mut step = mk_step(pos, delta, base.len(), 0, false, vec![]);
    step.declared_base_len = declared_base as usize;
    step.declared_target_len = declared_target as usize;

    if declared_base as usize != base.len() {
        checks.push(format!(
            "base 长度校验失败: 声明 {} 实际 {}",
            declared_base,
            base.len()
        ));
        step.checks = checks;
        return Err((
            format!("delta base 长度不匹配: 声明 {} 实际 {}", declared_base, base.len()),
            step,
        ));
    }
    checks.push(format!("base 长度校验通过 ({})", base.len()));

    let instr_start = pos;
    let mut out: Vec<u8> = Vec::with_capacity(declared_target as usize);
    while pos < delta.len() {
        let cmd = delta[pos];
        pos += 1;
        if cmd & 0x80 != 0 {
            // copy from base
            let mut cp_off: u64 = 0;
            let mut cp_size: u64 = 0;
            for i in 0..4 {
                if cmd & (1 << i) != 0 {
                    if pos >= delta.len() {
                        step.checks = checks;
                        return Err(("copy 指令 offset 截断".to_string(), step));
                    }
                    cp_off |= (delta[pos] as u64) << (8 * i);
                    pos += 1;
                }
            }
            for i in 0..3 {
                if cmd & (0x10 << i) != 0 {
                    if pos >= delta.len() {
                        step.checks = checks;
                        return Err(("copy 指令 size 截断".to_string(), step));
                    }
                    cp_size |= (delta[pos] as u64) << (8 * i);
                    pos += 1;
                }
            }
            if cp_size == 0 {
                cp_size = 0x10000;
            }
            let end = cp_off as usize + cp_size as usize;
            if end > base.len() {
                checks.push(format!(
                    "copy 越界: offset {} size {} 超出 base 长度 {}",
                    cp_off,
                    cp_size,
                    base.len()
                ));
                step.checks = checks;
                return Err((format!("copy 指令越界 (offset {cp_off} size {cp_size})"), step));
            }
            out.extend_from_slice(&base[cp_off as usize..end]);
        } else if cmd != 0 {
            // insert literal
            let n = cmd as usize;
            if pos + n > delta.len() {
                step.checks = checks;
                return Err(("insert 指令数据截断".to_string(), step));
            }
            out.extend_from_slice(&delta[pos..pos + n]);
            pos += n;
        } else {
            step.checks = checks;
            return Err(("非法的 delta 指令 0x00".to_string(), step));
        }
    }
    step.instr_range = (instr_start, pos);
    step.output_len = out.len();
    if out.len() != declared_target as usize {
        checks.push(format!(
            "输出长度校验失败: 声明 {} 实际 {}",
            declared_target,
            out.len()
        ));
        step.checks = checks;
        return Err((
            format!("delta 输出大小欺骗: 声明 {} 实际 {}", declared_target, out.len()),
            step,
        ));
    }
    checks.push(format!("输出长度校验通过 ({})", out.len()));
    step.ok = true;
    step.checks = checks;
    Ok((out, step))
}

/// Git delta varint (little-endian 7-bit groups).
pub fn read_varint(data: &[u8], pos: usize) -> Option<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    let mut i = pos;
    loop {
        let b = *data.get(i)?;
        result |= ((b & 0x7f) as u64) << shift;
        i += 1;
        if b & 0x80 == 0 {
            return Some((result, i - pos));
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
}
