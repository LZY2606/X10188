//! 基于 flate2 的原始 zlib 解压，额外保留压缩流边界。
//!
//! Git pack 条目 = `[size/type varint header][zlib stream]`，每个 zlib 流必须
//! 完整（2 字节 zlib header + deflate 数据 + 4 字节 adler32）。我们需要知道
//! 流精确消耗了多少字节，才能：
//! 1. 对“下一个对象”继续定位；
//! 2. 取压缩字节做 index CRC32 校验；
//! 3. 识别“解压到一半截断”“条目之间有垃圾字节”等异常。

use flate2::DecompressError;
use flate2::FlushDecompress;
use flate2::Status;
use flate2::Decompress;

use crate::types::{Evidence, InflateOutcome};

/// 解压硬上限：防止伪造/炸弹对象吃掉内存。
pub const INFLATE_HARD_LIMIT: usize = 256 * 1024 * 1024;

#[derive(Debug)]
pub struct InflateError {
    pub message: String,
    /// 已经解出的字节（可能非空），用于“解压到一半才发现问题”取证。
    pub partial: Vec<u8>,
    pub consumed_in: usize,
}

impl InflateError {
    fn new(message: impl Into<String>, partial: Vec<u8>, consumed_in: usize) -> Self {
        InflateError { message: message.into(), partial, consumed_in }
    }
}

impl From<DecompressError> for InflateError {
    fn from(e: DecompressError) -> Self {
        InflateError::new(e.to_string(), Vec::new(), 0)
    }
}

/// 从 `input[start..]` 解压一个完整 zlib 流。
///
/// * `expected_size`：来自 pack header 的声明大小。若提供，则要求解出长度必须
///   与声明一致，否则报“大小欺骗”。
/// * 解压成功后，`InflateOutcome.comp_len` 是 zlib 流精确长度。
pub fn inflate_stream(
    input: &[u8],
    start: usize,
    expected_size: Option<u64>,
) -> Result<InflateOutcome, InflateError> {
    if start + 1 >= input.len() {
        return Err(InflateError::new("zlib 数据起点超出文件长度", Vec::new(), 0));
    }
    let cmf = input[start];
    let flg = input[start + 1];
    if cmf & 0x0f != 8 || (cmf as u16 * 256 + flg as u16) % 31 != 0 {
        return Err(InflateError::new(
            "非法 zlib header（CMF/FLG 不合法，疑似伪造或截断）",
            Vec::new(),
            0,
        ));
    }

    let mut dec = Decompress::new(false);
    let mut out: Vec<u8> = Vec::new();
    let mut next_in = start;

    loop {
        if out.len() >= INFLATE_HARD_LIMIT {
            return Err(InflateError::new(
                format!("解压超过 {INFLATE_HARD_LIMIT} 字节硬上限，疑似解压炸弹"),
                out,
                next_in - start,
            ));
        }
        if next_in >= input.len() {
            return Err(InflateError::new(
                "zlib 流在结束前被截断（输入耗尽，缺少 deflate 尾或 adler32）",
                out,
                next_in - start,
            ));
        }
        let in_before = dec.total_in();
        let out_before = out.len();
        out.resize((out.len() + 16 * 1024).min(INFLATE_HARD_LIMIT + 1), 0);
        let status = dec.decompress(&input[next_in..], &mut out[out_before..], FlushDecompress::None);
        next_in += (dec.total_in() - in_before) as usize;
        out.truncate(dec.total_out() as usize);

        match status {
            Ok(Status::StreamEnd) => break,
            Ok(Status::Ok) | Ok(Status::BufError) => {
                if dec.total_in() as usize == next_in - start && dec.total_out() as usize == out_before {
                    return Err(InflateError::new("zlib 解压停滞", out, next_in - start));
                }
            }
            Err(e) => {
                return Err(InflateError::new(
                    format!("zlib 数据错误：{e}（可能解压到一半才发现大小/内容欺骗）"),
                    out,
                    next_in - start,
                ));
            }
        }
    }

    let comp_len = dec.total_in() as usize;
    let trailing = input.len() - start - comp_len;

    if let Some(expected) = expected_size {
        if out.len() as u64 != expected {
            return Err(InflateError::new(
                format!("大小欺骗：header 声明 {expected} 字节，实际解出 {} 字节", out.len()),
                out,
                comp_len,
            ));
        }
    }

    Ok(InflateOutcome {
        data: out,
        comp_start: start,
        comp_len,
        stream_finished: true,
        trailing,
    })
}

/// 把一次解压错误归类成错误码证据。
pub fn evidence_for(err: &InflateError, abs_offset: u64) -> Evidence {
    let code = if err.message.contains("大小欺骗") {
        "size_spoof"
    } else if err.message.contains("截断") {
        "truncated_zlib"
    } else if err.message.contains("硬上限") {
        "inflate_bomb"
    } else if err.message.contains("zlib header") {
        "bad_zlib_header"
    } else {
        "zlib_error"
    };
    Evidence::new(code, err.message.clone(), Some(abs_offset + err.consumed_in as u64), None)
}
