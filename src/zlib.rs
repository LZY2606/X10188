//! zlib 流解压与边界探测（miniz_oxide，纯 Rust）。

use std::convert::TryInto;

/// 解压结果。
pub struct Inflated {
    pub data: Vec<u8>,
    /// 压缩流在输入中占用的字节数（zlib 边界）。
    pub consumed: usize,
    /// 输入声明的 zlib 校验和是否通过（ADLER32）。
    pub adler_ok: bool,
}

/// 从 `input[start..]` 解压一个完整 zlib 流。
///
/// `hard_cap`：输出字节硬上限（预算）。超过时返回 [`InflateError::CapExceeded`]，
/// 已解压部分丢弃——绝不把部分输出当成完整对象。
pub fn inflate_raw(input: &[u8], start: usize, hard_cap: u64) -> Result<Inflated, InflateError> {
    use miniz_oxide::inflate::core::decompress;
    use miniz_oxide::inflate::core::inflate_flags::{
        TINFL_FLAG_PARSE_ZLIB_HEADER, TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
    };
    use miniz_oxide::inflate::core::{DecompressorOxide, TINFLStatus};

    if input.get(start) != Some(&0x78) {
        return Err(InflateError::NotZlib);
    }
    let mut d = DecompressorOxide::new();
    let mut out: Vec<u8> = Vec::new();
    let mut in_pos = start;
    let chunk = 64 * 1024usize;
    let mut total_in = 0usize;
    let mut total_out = 0usize;

    loop {
        if total_out as u64 >= hard_cap {
            return Err(InflateError::CapExceeded);
        }
        let room = chunk.min(
            (hard_cap.saturating_sub(total_out as u64).min(chunk as u64).max(0)) as usize,
        );
        let prev_len = out.len();
        out.resize(prev_len + room, 0);
        let flags = TINFL_FLAG_PARSE_ZLIB_HEADER | TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF;
        let (status, in_used, out_used) = decompress(
            &mut d,
            &input[in_pos..],
            &mut out[prev_len..],
            flags,
            0,
        );
        in_pos += in_used;
        total_in += in_used;
        out.truncate(prev_len + out_used);
        total_out += out_used;

        if status == TINFLStatus::NeedsMoreInput
            && in_used == 0
            && in_pos >= input.len()
        {
            return Err(InflateError::Corrupt);
        }

        match status {
            TINFLStatus::Done => break,
            TINFLStatus::NeedsMoreInput if out_used == room && room > 0 => {
                if total_out as u64 >= hard_cap {
                    return Err(InflateError::CapExceeded);
                }
                continue;
            }
            TINFLStatus::NeedsMoreInput => continue,
            TINFLStatus::HasMoreOutput => {
                if total_out as u64 >= hard_cap {
                    return Err(InflateError::CapExceeded);
                }
                continue;
            }
            TINFLStatus::FailedCannotMakeProgress | TINFLStatus::BadParam => {
                return Err(InflateError::Corrupt);
            }
        }
    }

    if total_out as u64 > hard_cap {
        return Err(InflateError::CapExceeded);
    }

    // miniz 不单独回传 adler 校验结果；手动校验尾部 4 字节。
    let adler = adler32(&out);
    let trailer = input.get(in_pos - 4..in_pos).and_then(|s| s.try_into().ok());
    let adler_ok = matches!(
        trailer.map(u32::from_be_bytes),
        Some(want) if want == adler
    );

    Ok(Inflated {
        data: out,
        consumed: total_in,
        adler_ok,
    })
}

#[derive(Debug, PartialEq, Eq)]
pub enum InflateError {
    NotZlib,
    Corrupt,
    CapExceeded,
}

pub fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &x in data {
        a = (a + x as u32) % MOD;
        b = (b + a) % MOD;
    }
    (b << 16) | a
}

/// zlib 压缩（供测试造包）。
pub fn deflate_raw(data: &[u8]) -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    use std::io::Write;
    let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}
